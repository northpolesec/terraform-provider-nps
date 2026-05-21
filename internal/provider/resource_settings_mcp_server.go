// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &MCPServerSettingsResource{}
var _ resource.ResourceWithConfigure = &MCPServerSettingsResource{}
var _ resource.ResourceWithImportState = &MCPServerSettingsResource{}
var _ resource.ResourceWithIdentity = &MCPServerSettingsResource{}

func NewMCPServerSettingsResource() resource.Resource {
	return &MCPServerSettingsResource{}
}

type MCPServerSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type MCPServerSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type MCPServerSettingsResourceModel struct {
	Enabled   types.Bool `tfsdk:"enabled"`
	ReadWrite types.Bool `tfsdk:"read_write"`
}

func (r *MCPServerSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_mcp_server"
}

func (r *MCPServerSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_mcp_server resource manages the MCP server settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",
		MarkdownDescription: "The `nps_workshop_settings_mcp_server` resource manages the MCP server settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",

		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Description:         "Whether the MCP server is enabled.",
				MarkdownDescription: "Whether the MCP server is enabled.",
				Optional:            true,
			},
			"read_write": schema.BoolAttribute{
				Description:         "Whether the MCP server allows read-write operations. If false, the server is read-only.",
				MarkdownDescription: "Whether the MCP server allows read-write operations. If false, the server is read-only.",
				Optional:            true,
			},
		},
	}
}

func (r *MCPServerSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	pd, ok := req.ProviderData.(*NPSProviderResourceData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected NPSProviderResourceData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = pd.Client
}

func (r *MCPServerSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data MCPServerSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	b := apipb.UpdateMCPServerSettingsRequest_builder{
		Enabled:   tfBoolToPtr(data.Enabled),
		ReadWrite: tfBoolToPtr(data.ReadWrite),
	}
	if _, err := r.client.UpdateMCPServerSettings(ctx, b.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update MCP server settings: %v", err))
		return
	}

	tflog.Info(ctx, "Created MCP server settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, MCPServerSettingsIdentityModel{Id: types.StringValue("mcp_server_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *MCPServerSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetMCPServerSettings(ctx, apipb.GetMCPServerSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get MCP server settings: %v", err))
		return
	}

	data := MCPServerSettingsResourceModel{
		Enabled:   boolPtrToTF(ret.Enabled),
		ReadWrite: boolPtrToTF(ret.ReadWrite),
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, MCPServerSettingsIdentityModel{Id: types.StringValue("mcp_server_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *MCPServerSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state MCPServerSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Partial update: UpdateMCPServerSettings only updates fields that are
	// explicitly set on the request. Compute which fields changed in the plan
	// versus the prior state and only include those.
	b := apipb.UpdateMCPServerSettingsRequest_builder{}
	if !plan.Enabled.Equal(state.Enabled) {
		b.Enabled = tfBoolToPtr(plan.Enabled)
	}
	if !plan.ReadWrite.Equal(state.ReadWrite) {
		b.ReadWrite = tfBoolToPtr(plan.ReadWrite)
	}

	if b.Enabled != nil || b.ReadWrite != nil {
		if _, err := r.client.UpdateMCPServerSettings(ctx, b.Build()); err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update MCP server settings: %v", err))
			return
		}
		tflog.Info(ctx, "Updated MCP server settings")
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, MCPServerSettingsIdentityModel{Id: types.StringValue("mcp_server_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *MCPServerSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Singleton: removing the resource from Terraform state does not modify
	// the server-side configuration.
	tflog.Info(ctx, "Removed MCP server settings from Terraform state (server-side configuration unchanged)")
}

func (r *MCPServerSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &MCPServerSettingsResourceModel{})...)
}

func (r *MCPServerSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}
