package common

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/integrations/lib/testing/integration"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTerraformCommand_createRoleIfNeeded(t *testing.T) {
	// Test setup
	authHelper := integration.MinimalAuthHelper{}
	adminClient := authHelper.StartServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Setting labels allows us to check whether the role
	// has been updated by the helper or not.
	defaultLabels := terraformRoleSpec.Allow.AppLabels
	testLabels := types.Labels{"foo": []string{"bar"}}
	existingRoleSpec := terraformRoleSpec
	existingRoleSpec.Allow.AppLabels = testLabels

	newRoleFixture := func(t *testing.T, name string) types.Role {
		role, err := types.NewRole(name, existingRoleSpec)
		require.NoError(t, err)
		return role
	}

	tests := []struct {
		name string
		// Test setup
		resourcePrefixFlag string
		existingRoleFlag   string
		fixture            types.Role
		// Test validation
		wantErr               require.ErrorAssertionFunc
		expectedRoleName      string
		expectedRoleAppLabels types.Labels
	}{
		{
			name:                  "Create role when not exist",
			wantErr:               require.NoError,
			expectedRoleAppLabels: defaultLabels,
			expectedRoleName:      terraformHelperDefaultResourcePrefix + "provider",
		},
		{
			name:                  "Update existing role",
			fixture:               newRoleFixture(t, terraformHelperDefaultResourcePrefix+"provider"),
			wantErr:               require.NoError,
			expectedRoleAppLabels: defaultLabels,
			expectedRoleName:      terraformHelperDefaultResourcePrefix + "provider",
		},
		{
			name:                  "Honour resource prefix",
			resourcePrefixFlag:    "test-",
			wantErr:               require.NoError,
			expectedRoleName:      "test-provider",
			expectedRoleAppLabels: defaultLabels,
		},
		{
			name:                  "Does not change existing role",
			existingRoleFlag:      "existing-role",
			fixture:               newRoleFixture(t, "existing-role"),
			wantErr:               require.NoError,
			expectedRoleName:      "existing-role",
			expectedRoleAppLabels: testLabels,
		},
		{
			name:             "Fails if existing role is not found",
			existingRoleFlag: "existing-role",
			wantErr:          require.Error,
		},
	}
	for _, tt := range tests {
		// Warning: Those tests cannot be run in parallel
		t.Run(tt.name, func(t *testing.T) {
			// Test case setup
			if tt.fixture != nil {
				_, err := adminClient.CreateRole(ctx, tt.fixture)
				require.NoError(t, err)
			}
			// mimick the kingpin default behaviour
			resourcePrefix := tt.resourcePrefixFlag
			if resourcePrefix == "" {
				resourcePrefix = terraformHelperDefaultResourcePrefix
			}

			// Test execution
			c := &TerraformCommand{
				resourcePrefix: resourcePrefix,
				existingRole:   tt.existingRoleFlag,
			}
			roleName, err := c.createRoleIfNeeded(ctx, adminClient)
			tt.wantErr(t, err)
			require.Equal(t, tt.expectedRoleName, roleName)
			if tt.expectedRoleAppLabels != nil {
				gotRole, err := adminClient.GetRole(ctx, roleName)
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(tt.expectedRoleAppLabels, gotRole.GetAppLabels(types.Allow)))
			}

			// Test cleanup
			if roleName != "" {
				err = adminClient.DeleteRole(ctx, roleName)
				if !trace.IsNotFound(err) {
					require.NoError(t, err)
				}
			}
		})
	}
}

func Test_identityToTerraformEnvVars(t *testing.T) {

}
