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
	"github.com/gravitational/teleport/lib/tbot/identity"
	"github.com/gravitational/teleport/lib/tbot/ssh"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
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
	// If we're not actively debugging, neutralize any kind of logging from other teleport components
	if !c.cfg.Debug {
		utils.InitLogger(utils.LoggingForCLI, slog.LevelError)
	}

	showProgress("Detecting if MFA is required")
	// TODO: check parameters (bot TTL != 0)
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
	showProgress("Using the temporary bot to obtain certificates 🤖")
	envVars, err := c.getCertsAndEnvVars(ctx, tokenName, client)
	if err != nil {
		return trace.Wrap(err)
	}

	showProgress("Certificates obtained, you can now use Terraform in this terminal 🚀")
	for env, value := range envVars {
		fmt.Printf("export %s=%q\n", env, value)
	}
	fmt.Println("# invoke this command in an eval: eval $(tctl terraform-helper)")
	return nil
}

func (c *TerraformCommand) createTransientBotAndToken(ctx context.Context, client *authclient.Client, roleName string) (string, error) {
	// Create token and bot name
	suffix, err := utils.CryptoRandomHex(4)
	if err != nil {
		return "", trace.Wrap(err)
	}

	botName := c.resourcePrefix + "-" + suffix
	showProgress(fmt.Sprintf("Creating temporary bot %q and its token", botName))

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

func (c *TerraformCommand) getCertsAndEnvVars(ctx context.Context, token string, clt *authclient.Client) (map[string]string, error) {
	log := slog.Default()

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

	addrs := c.cfg.AuthServerAddresses()
	if len(addrs) == 0 {
		return nil, trace.BadParameter("no auth server addresses found")
	}
	addr := addrs[0]
	// When invoked only with auth address, tbot will try both joining as an auth and as a proxy.
	// This allows us to not care about how the user connects to Teleport
	cfg.AuthServer = addr.String()

	localCAResponse, err := clt.GetClusterCACert(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	caPins, err := tlsca.CalculatePins(localCAResponse.TLSCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cfg.Onboarding.CAPins = caPins
	log.DebugContext(ctx, "Using auth address", "addr", cfg.AuthServer)

	err = cfg.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	bot := tbot.New(cfg, slog.Default())
	err = bot.Run(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	facade, err := credential.Facade()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	id := facade.Get()

	// Workaround for https://github.com/gravitational/teleport-private/issues/1572
	clusterName, err := clt.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	knownHosts, err := ssh.GenerateKnownHosts(ctx, clt, []string{clusterName.GetClusterName()}, addr.Host())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	id.SSHCACertBytes = [][]byte{
		[]byte(knownHosts),
	}
	// End of workaround

	return generateEnvVars(addr.String(), id)
}

func showProgress(update string) {
	_, _ = fmt.Fprintln(os.Stderr, update)
}

func generateEnvVars(addr string, id *identity.Identity) (map[string]string, error) {
	// keyBase64 := base64.StdEncoding.EncodeToString(id.PrivateKeyBytes)
	// certBase64 := base64.StdEncoding.EncodeToString(id.TLSCertBytes)
	// caBundle := bytes.Join(id.TLSCACertsBytes, []byte("\n"))
	// caCertsBase64 := base64.StdEncoding.EncodeToString(caBundle)
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
		return nil, trace.Wrap(err)
	}
	idBase64 := base64.StdEncoding.EncodeToString(idBytes)
	return map[string]string{
		EnvVarTerraformAddress: addr,
		//	EnvVarTerraformCert:     certBase64,
		//	EnvVarTerraformKey:      keyBase64,
		//	EnvVarTerraformCACert:   caCertsBase64,
		EnvVarTerraformIdentity: idBase64,
	}, nil

}

const (
	EnvVarTerraformAddress  = "TF_TELEPORT_ADDR"
	EnvVarTerraformIdentity = "TF_TELEPORT_IDENTITY_FILE_BASE64"
	EnvVarTerraformCert     = "TF_TELEPORT_CERT_BASE64"
	EnvVarTerraformKey      = "TF_TELEPORT_KEY_BASE64"
	EnvVarTerraformCACert   = "TF_TELEPORT_CA_BASE64"
)
