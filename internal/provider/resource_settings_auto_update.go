// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	Mode       types.String `tfsdk:"mode"`
	StartHour  types.Int64  `tfsdk:"start_hour"`
	EndHour    types.Int64  `tfsdk:"end_hour"`
	DaysOfWeek types.Set    `tfsdk:"days_of_week"`
}

// autoUpdateSettings builds the full AutoUpdateSettings message from the
// model. UpdateAutoUpdateSettings replaces the whole message rather than
// merging, so every field the schema models has to be sent on every call, and
// any field it does not model would be erased.
func autoUpdateSettings(ctx context.Context, data AutoUpdateSettingsResourceModel, diags *diag.Diagnostics) *apipb.AutoUpdateSettings {
	return apipb.AutoUpdateSettings_builder{
		Mode:       apipb.AutoUpdateMode(apipb.AutoUpdateMode_value[data.Mode.ValueString()]),
		StartHour:  tfInt64ToInt32Ptr(data.StartHour),
		EndHour:    tfInt64ToInt32Ptr(data.EndHour),
		DaysOfWeek: tfInt64SetToInt32s(ctx, data.DaysOfWeek, diags),
	}.Build()
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
			"days_of_week": schema.SetAttribute{
				Description:         "The days of the week in UTC on which updates are allowed, as 0 (Sunday) through 6 (Saturday). Leave unset to allow updates on any day; an empty set means the same thing and is rejected so the two spellings cannot diff against each other. Combined with start_hour and end_hour to restrict updates to e.g. Monday nights only.",
				MarkdownDescription: "The days of the week in UTC on which updates are allowed, as `0` (Sunday) through `6` (Saturday). Leave unset to allow updates on any day; an empty set means the same thing and is rejected so the two spellings cannot diff against each other. Combined with `start_hour` and `end_hour` to restrict updates to e.g. Monday nights only.",
				Optional:            true,
				ElementType:         types.Int64Type,
				Validators: []validator.Set{
					// An empty set and an unset attribute both mean "any day" on a
					// plain repeated field, and the server cannot report the
					// difference back, so only one of the two spellings can survive
					// a refresh. Reject the redundant one rather than let it diff on
					// every plan. SizeAtMost mirrors the proto's max_items; a set
					// already gives the uniqueness it also requires.
					setvalidator.SizeBetween(1, 7),
					setvalidator.ValueInt64sAre(int64validator.Between(0, 6)),
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

	settings := autoUpdateSettings(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := r.client.UpdateAutoUpdateSettings(ctx, apipb.UpdateAutoUpdateSettingsRequest_builder{Settings: settings}.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update auto-update settings: %v", err))
		return
	}

	tflog.Info(ctx, "Created auto-update settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, AutoUpdateSettingsIdentityModel{Id: types.StringValue("auto_update_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AutoUpdateSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AutoUpdateSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ret, err := r.client.GetAutoUpdateSettings(ctx, apipb.GetAutoUpdateSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get auto-update settings: %v", err))
		return
	}

	if s := ret.GetSettings(); s != nil {
		// A tenant with no stored settings reports AUTO_UPDATE_MODE_UNSPECIFIED,
		// which is not valid configuration: writing it would leave state that the
		// schema's own OneOf validator rejects on the next plan. Keep the prior
		// value instead.
		if s.GetMode() != apipb.AutoUpdateMode_AUTO_UPDATE_MODE_UNSPECIFIED {
			data.Mode = types.StringValue(s.GetMode().String())
		}
		data.StartHour = int32PtrToTFInt64(s.StartHour)
		data.EndHour = int32PtrToTFInt64(s.EndHour)
		data.DaysOfWeek = int32sToTFInt64Set(ctx, s.GetDaysOfWeek(), &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
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

	settings := autoUpdateSettings(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

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
	// Placeholder state; Read is invoked immediately after import and
	// overwrites this with the authoritative server values. The placeholder
	// must satisfy the schema's OneOf validator on Mode.
	resp.Diagnostics.Append(resp.State.Set(ctx, &AutoUpdateSettingsResourceModel{
		Mode: types.StringValue("AUTO_UPDATE_MODE_DISABLED"),
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
