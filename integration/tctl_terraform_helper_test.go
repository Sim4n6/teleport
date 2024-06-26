package integration

import (
	"github.com/google/uuid"
	"github.com/gravitational/teleport/integration/helpers"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestTCTLTerraformCommand_ProxyJoin(t *testing.T) {
	testDir := t.TempDir()

	clusterName := "root.example.com"
	cfg := helpers.InstanceConfig{
		ClusterName: clusterName,
		HostID:      uuid.New().String(),
		NodeName:    helpers.Loopback,
		Log:         utils.NewLoggerForTests(),
	}
	cfg.Listeners = helpers.SingleProxyPortSetup(t, &cfg.Fds)
	rc := helpers.NewInstance(t, cfg)

	rcConf := servicecfg.MakeDefaultConfig()
	rcConf.DataDir = filepath.Join(testDir, "data")
	rcConf.Auth.Enabled = true
	rcConf.Proxy.Enabled = true
	rcConf.SSH.Enabled = false
	rcConf.Proxy.DisableWebInterface = true
	rcConf.Version = "v3"

	err := rc.CreateEx(t, nil, rcConf)
	require.NoError(t, err)

	err = rc.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, rc.StopAll())
	})

	auth := rc.GetSiteAPI(clusterName)
	authClient, ok := auth.(*authclient.Client)
	require.True(t, ok)
	authClient

}

func TestTCTLTerraformCommand_AuthJoin(t *testing.T) {

}
