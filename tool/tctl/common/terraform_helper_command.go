package common

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/alecthomas/kingpin/v2"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	machineidv1pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/machineid/v1"
	"github.com/gravitational/teleport/api/identityfile"
	"github.com/gravitational/teleport/api/mfa"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/tbot"
	"github.com/gravitational/teleport/lib/tbot/config"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	logutils "github.com/gravitational/teleport/lib/utils/log"
	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/timestamppb"
	"log/slog"
	"os"
	"time"
)

type TerraformCommand struct {
	format string

	resourcePrefix string
	existingRole   string
	botTTL         time.Duration

	cfg *servicecfg.Config

	cmd *kingpin.CmdClause
}

var terraformRoleSpec = types.RoleSpecV6{
	Allow: types.RoleConditions{
		AppLabels:      map[string]apiutils.Strings{types.Wildcard: []string{types.Wildcard}},
		DatabaseLabels: map[string]apiutils.Strings{types.Wildcard: []string{types.Wildcard}},
		NodeLabels:     map[string]apiutils.Strings{types.Wildcard: []string{types.Wildcard}},
		Rules: []types.Rule{
			{
				Resources: []string{
					types.KindUser, types.KindRole, types.KindToken, types.KindTrustedCluster, types.KindGithub,
					types.KindOIDC, types.KindSAML, types.KindClusterAuthPreference, types.KindClusterNetworkingConfig,
					types.KindClusterMaintenanceConfig, types.KindSessionRecordingConfig, types.KindApp,
					types.KindDatabase, types.KindLoginRule, types.KindDevice, types.KindOktaImportRule,
					types.KindAccessList, types.KindNode,
				},
				Verbs: []string{types.VerbList, types.VerbCreate, types.VerbRead, types.VerbUpdate, types.VerbDelete},
			},
		},
	},
}

// Initialize sets up the "tctl bots" command.
func (c *TerraformCommand) Initialize(app *kingpin.Application, cfg *servicecfg.Config) {
	c.cmd = app.Command("terraform-helper", "Bootstrap resources and obtain certificates to run the Teleport Terraform provider locally.")
	c.cmd.Flag("resource-prefix", "Resource prefix to use for resources.").Default("terraform-provider").StringVar(&c.resourcePrefix)
	c.cmd.Flag("bot-ttl", "Time-to-live of the bootstrapped bot resource. The bot will be removed after this period.").Default("1h").DurationVar(&c.botTTL)
	c.cmd.Flag("use-existing-role", "Existing Terraform role to use instead of creating a new one.").StringVar(&c.existingRole)

	// Save a pointer to the config to be able to recover the Debug config later
	c.cfg = cfg
}

// TryRun attempts to run subcommands.
func (c *TerraformCommand) TryRun(ctx context.Context, cmd string, client *authclient.Client) (match bool, err error) {
	switch cmd {
	case c.cmd.FullCommand():
		err = c.Bootstrap(ctx, client)
	default:
		return false, nil
	}

	return true, trace.Wrap(err)
}

func (c *TerraformCommand) Bootstrap(ctx context.Context, client *authclient.Client) error {
	// TODO: check parameters (bot TTL != 0)
	log := slog.Default()
	log.InfoContext(ctx, "Detecting if MFA is required")

	// Prompt for admin action MFA if required, allowing reuse for UpsertRole, UpsertToken and CreateBot.
	mfaResponse, err := mfa.PerformAdminActionMFACeremony(ctx, client.PerformMFACeremony, true /*allowReuse*/)
	if err == nil {
		ctx = mfa.ContextWithMFAResponse(ctx, mfaResponse)
	} else if !errors.Is(err, &mfa.ErrMFANotRequired) && !errors.Is(err, &mfa.ErrMFANotSupported) {
		return trace.Wrap(err)
	}

	roleName, err := c.createRoleIfNeeded(ctx, client)
	if err != nil {
		return trace.Wrap(err)
	}

	tokenName, err := c.createTransientBotAndToken(ctx, client, roleName)
	if err != nil {
		return trace.Wrap(err)
	}

	// Now run tbot
	id, err := c.getCertsForBot(ctx, tokenName, client)
	if err != nil {
		return trace.Wrap(err)
	}

	log.InfoContext(ctx, "Certificates obtained")
	fmt.Println("# invoke this command in an eval: eval $(tctl terraform-helper)")
	fmt.Printf("export TF_TELEPORT_IDENTITY_FILE_BASE64='%s'\n", id)
	fmt.Fprintf(os.Stderr, "Lets gooooo, cert valid for %s 🚀", c.botTTL.String())
	return nil
}

func (c *TerraformCommand) createTransientBotAndToken(ctx context.Context, client *authclient.Client, roleName string) (string, error) {
	log := slog.Default()
	// Create token and bot name
	suffix, err := utils.CryptoRandomHex(10)
	if err != nil {
		return "", trace.Wrap(err)
	}

	botName := c.resourcePrefix + "-" + suffix
	log.InfoContext(ctx, "Creating temporary bot and token", "bot", botName, "ttl", c.botTTL.String())

	roles := []string{roleName}
	var token types.ProvisionToken

	// Generate a token
	tokenName, err := utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return "", trace.Wrap(err)
	}
	ttl := c.botTTL
	tokenSpec := types.ProvisionTokenSpecV2{
		Roles:      types.SystemRoles{types.RoleBot},
		JoinMethod: types.JoinMethodToken,
		BotName:    botName,
	}
	token, err = types.NewProvisionTokenFromSpec(tokenName, time.Now().Add(ttl), tokenSpec)
	if err != nil {
		return "", trace.Wrap(err)
	}
	if err := client.UpsertToken(ctx, token); err != nil {
		return "", trace.Wrap(err)
	}

	// Create bot
	bot := &machineidv1pb.Bot{
		Metadata: &headerv1.Metadata{
			Name:    botName,
			Expires: timestamppb.New(time.Now().Add(c.botTTL)),
		},
		Spec: &machineidv1pb.BotSpec{
			Roles: roles,
		},
	}

	bot, err = client.BotServiceClient().CreateBot(ctx, &machineidv1pb.CreateBotRequest{
		Bot: bot,
	})
	if err != nil {
		return "", trace.Wrap(err)
	}
	return tokenName, nil
}

func (c *TerraformCommand) createRoleIfNeeded(ctx context.Context, client *authclient.Client) (string, error) {
	log := slog.Default()

	roleName := c.existingRole
	// Create role if --use-existing-role is not set
	if roleName == "" {
		roleName = c.resourcePrefix
		log.InfoContext(ctx, "Creating the Terraform role", "role", roleName)
		role, err := types.NewRole(roleName, terraformRoleSpec)
		if err != nil {
			return "", trace.Wrap(err)
		}
		_, err = client.UpsertRole(ctx, role)
		if err != nil {
			return "", trace.Wrap(err)
		}
	} else {
		// Else we check if te role exists
		log.InfoContext(ctx, "Reusing existing Terraform role", "role", roleName)
		// TODO: get the role
	}
	return roleName, nil
}

func (c *TerraformCommand) getCertsForBot(ctx context.Context, token string, clt *authclient.Client) (string, error) {
	log := slog.Default()
	log.InfoContext(ctx, "Using the temporary bot to obtain certificates")

	credential := &config.UnstableClientCredentialOutput{}
	cfg := &config.BotConfig{
		Version: "",
		Onboarding: config.OnboardingConfig{
			TokenValue: token,
			JoinMethod: types.JoinMethodToken,
		},
		Storage:        &config.StorageConfig{Destination: &config.DestinationMemory{}},
		Outputs:        []config.Output{credential},
		CertificateTTL: c.botTTL,
		Oneshot:        true,
	}

	if addrs := c.cfg.AuthServerAddresses(); len(addrs) > 0 {
		cfg.AuthServer = addrs[0].String()
		localCAResponse, err := clt.GetClusterCACert(ctx)
		if err != nil {
			return "", trace.Wrap(err)
		}
		caPins, err := tlsca.CalculatePins(localCAResponse.TLSCA)
		if err != nil {
			return "", trace.Wrap(err)
		}
		cfg.Onboarding.CAPins = caPins
		log.DebugContext(ctx, "Using auth address", "addr", cfg.AuthServer)
	} else {
		cfg.ProxyServer = c.cfg.ProxyServer.String()
		log.DebugContext(ctx, "Using proxy address", "addr", cfg.ProxyServer)
	}
	err := cfg.CheckAndSetDefaults()
	if err != nil {
		return "", trace.Wrap(err)
	}

	bot := tbot.New(cfg, log)
	err = bot.Run(ctx)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return c.b64IdFromCredential(credential)
}

func (c *TerraformCommand) b64IdFromCredential(credential *config.UnstableClientCredentialOutput) (string, error) {
	facade, err := credential.Facade()
	if err != nil {
		return "", trace.Wrap(err)
	}
	id := facade.Get()
	idFile := &identityfile.IdentityFile{
		PrivateKey: id.PrivateKeyBytes,
		Certs: identityfile.Certs{
			SSH: id.CertBytes,
			TLS: id.TLSCertBytes,
		},
		CACerts: identityfile.CACerts{
			SSH: id.SSHCACertBytes,
			TLS: id.TLSCACertsBytes,
		},
	}
	idBytes, err := identityfile.Encode(idFile)
	if err != nil {
		return "", trace.Wrap(err)
	}
	idBase64 := base64.StdEncoding.EncodeToString(idBytes)
	return idBase64, nil
}

func (c *TerraformCommand) loggerForTBot() *slog.Logger {
	// We don't want to spam the user with tbot's INFO logs so we use Warn by default
	tbotLogLevel := slog.LevelError
	if c.cfg.Debug {
		// Unless we are debugging something, in this case the user do want to get spammed
		tbotLogLevel = slog.LevelDebug
	}

	enableColors := utils.IsTerminal(os.Stderr)
	w := logutils.NewSharedWriter(os.Stderr)
	handler := logutils.NewSlogTextHandler(w, logutils.SlogTextHandlerConfig{
		Level:        tbotLogLevel,
		EnableColors: enableColors,
	})
	return slog.New(handler)
}
