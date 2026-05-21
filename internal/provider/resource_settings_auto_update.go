// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &AutoUpdateSettingsResource{}
var _ resource.ResourceWithConfigure = &AutoUpdateSettingsResource{}
var _ resource.ResourceWithImportState = &AutoUpdateSettingsResource{}
var _ resource.ResourceWithIdentity = &AutoUpdateSettingsResource{}

func NewAutoUpdateSettingsResource() resource.Resource {
	return &AutoUpdateSettingsResource{}
}

type AutoUpdateSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type AutoUpdateSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type AutoUpdateSettingsResourceModel struct {
	Mode      types.String `tfsdk:"mode"`
	StartHour types.Int64  `tfsdk:"start_hour"`
	EndHour   types.Int64  `tfsdk:"end_hour"`
}

func (r *AutoUpdateSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_auto_update"
}

func (r *AutoUpdateSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_auto_update resource manages the auto-update settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",
		MarkdownDescription: "The `nps_workshop_settings_auto_update` resource manages the auto-update settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",

		Attributes: map[string]schema.Attribute{
			"mode": schema.StringAttribute{
				Description:         "The auto-update mode. Must be one of: AUTO_UPDATE_MODE_DISABLED, AUTO_UPDATE_MODE_ENABLED_ALL, AUTO_UPDATE_MODE_ENABLED_SECURITY_ONLY.",
				MarkdownDescription: "The auto-update mode. Must be one of: `AUTO_UPDATE_MODE_DISABLED`, `AUTO_UPDATE_MODE_ENABLED_ALL`, `AUTO_UPDATE_MODE_ENABLED_SECURITY_ONLY`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"AUTO_UPDATE_MODE_DISABLED",
						"AUTO_UPDATE_MODE_ENABLED_ALL",
						"AUTO_UPDATE_MODE_ENABLED_SECURITY_ONLY",
					),
				},
			},
			"start_hour": schema.Int64Attribute{
				Description:         "The start hour of the update window in UTC (0-23). If both start_hour and end_hour are unset and mode is not disabled, updates can occur at any hour.",
				MarkdownDescription: "The start hour of the update window in UTC (0-23). If both `start_hour` and `end_hour` are unset and mode is not disabled, updates can occur at any hour.",
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 23),
				},
			},
			"end_hour": schema.Int64Attribute{
				Description:         "The end hour of the update window in UTC (0-23). Supports overnight windows: if start_hour > end_hour, the window wraps around midnight.",
				MarkdownDescription: "The end hour of the update window in UTC (0-23). Supports overnight windows: if `start_hour > end_hour`, the window wraps around midnight.",
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 23),
				},
			},
		},
	}
}

func (r *AutoUpdateSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *AutoUpdateSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AutoUpdateSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mode := apipb.AutoUpdateMode(apipb.AutoUpdateMode_value[data.Mode.ValueString()])
	settings := apipb.AutoUpdateSettings_builder{
		Mode:      mode,
		StartHour: tfInt64ToInt32Ptr(data.StartHour),
		EndHour:   tfInt64ToInt32Ptr(data.EndHour),
	}.Build()

	if _, err := r.client.UpdateAutoUpdateSettings(ctx, apipb.UpdateAutoUpdateSettingsRequest_builder{Settings: settings}.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update auto-update settings: %v", err))
		return
	}

	tflog.Info(ctx, "Created auto-update settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, AutoUpdateSettingsIdentityModel{Id: types.StringValue("auto_update_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AutoUpdateSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetAutoUpdateSettings(ctx, apipb.GetAutoUpdateSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get auto-update settings: %v", err))
		return
	}

	s := ret.GetSettings()
	data := AutoUpdateSettingsResourceModel{
		Mode:      types.StringValue(s.GetMode().String()),
		StartHour: int32PtrToTFInt64(s.StartHour),
		EndHour:   int32PtrToTFInt64(s.EndHour),
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, AutoUpdateSettingsIdentityModel{Id: types.StringValue("auto_update_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AutoUpdateSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan AutoUpdateSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// UpdateAutoUpdateSettings replaces the whole AutoUpdateSettings message;
	// it is not presence-sensitive, so we always send the full plan.
	mode := apipb.AutoUpdateMode(apipb.AutoUpdateMode_value[plan.Mode.ValueString()])
	settings := apipb.AutoUpdateSettings_builder{
		Mode:      mode,
		StartHour: tfInt64ToInt32Ptr(plan.StartHour),
		EndHour:   tfInt64ToInt32Ptr(plan.EndHour),
	}.Build()

	if _, err := r.client.UpdateAutoUpdateSettings(ctx, apipb.UpdateAutoUpdateSettingsRequest_builder{Settings: settings}.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update auto-update settings: %v", err))
		return
	}

	tflog.Info(ctx, "Updated auto-update settings")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, AutoUpdateSettingsIdentityModel{Id: types.StringValue("auto_update_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AutoUpdateSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed auto-update settings from Terraform state (server-side configuration unchanged)")
}

func (r *AutoUpdateSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &AutoUpdateSettingsResourceModel{
		Mode: types.StringValue("AUTO_UPDATE_MODE_UNSPECIFIED"),
	})...)
}

func (r *AutoUpdateSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}
