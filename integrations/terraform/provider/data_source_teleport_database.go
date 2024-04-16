// Code generated by _gen/main.go DO NOT EDIT
/*
Copyright 2015-2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"context"

	apitypes "github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	tfprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/gravitational/teleport/integrations/terraform/tfschema"
)

// dataSourceTeleportDatabaseType is the data source metadata type
type dataSourceTeleportDatabaseType struct{}

// dataSourceTeleportDatabase is the resource
type dataSourceTeleportDatabase struct {
	p Provider
}

// GetSchema returns the data source schema
func (r dataSourceTeleportDatabaseType) GetSchema(ctx context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfschema.GenSchemaDatabaseV3(ctx)
}

// NewDataSource creates the empty data source
func (r dataSourceTeleportDatabaseType) NewDataSource(_ context.Context, p tfprovider.Provider) (datasource.DataSource, diag.Diagnostics) {
	return dataSourceTeleportDatabase{
		p: *(p.(*Provider)),
	}, nil
}

// Read reads teleport Database
func (r dataSourceTeleportDatabase) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var id types.String
	diags := req.Config.GetAttribute(ctx, path.Root("metadata").AtName("name"), &id)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	databaseI, err := r.p.Client.GetDatabase(ctx, id.Value)
	if err != nil {
		resp.Diagnostics.Append(diagFromWrappedErr("Error reading Database", trace.Wrap(err), "db"))
		return
	}

    var state types.Object
	
	database := databaseI.(*apitypes.DatabaseV3)
	diags = tfschema.CopyDatabaseV3ToTerraform(ctx, database, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
