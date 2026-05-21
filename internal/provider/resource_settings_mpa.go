// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &MPASettingsResource{}
var _ resource.ResourceWithConfigure = &MPASettingsResource{}
var _ resource.ResourceWithImportState = &MPASettingsResource{}
var _ resource.ResourceWithIdentity = &MPASettingsResource{}

func NewMPASettingsResource() resource.Resource {
	return &MPASettingsResource{}
}

type MPASettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type MPASettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type MPASettingsResourceModel struct {
	Enabled           types.Bool   `tfsdk:"enabled"`
	MaxDuration       types.String `tfsdk:"max_duration"`
	RequiredApprovers types.Int64  `tfsdk:"required_approvers"`
	ExcludeApiKeys    types.Bool   `tfsdk:"exclude_api_keys"`
}

func (r *MPASettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_mpa"
}

func (r *MPASettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_mpa resource manages multi-party approval settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server. Note: if MPA is currently enabled on the server, changes to these settings may require approval from additional admins and will fail to apply immediately.",
		MarkdownDescription: "The `nps_workshop_settings_mpa` resource manages multi-party approval settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server. Note: if MPA is currently enabled on the server, changes to these settings may require approval from additional admins and will fail to apply immediately.",

		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Description:         "Whether multi-party approval is enabled for sensitive actions.",
				MarkdownDescription: "Whether multi-party approval is enabled for sensitive actions.",
				Optional:            true,
			},
			"max_duration": schema.StringAttribute{
				Description:         "Maximum duration an approval request remains pending before it expires. Go duration string (e.g. \"30m\", \"24h\").",
				MarkdownDescription: "Maximum duration an approval request remains pending before it expires. Go duration string (e.g. `\"30m\"`, `\"24h\"`).",
				Optional:            true,
			},
			"required_approvers": schema.Int64Attribute{
				Description:         "Number of workshop-admin approvals required before executing an action. The requestor cannot approve their own request.",
				MarkdownDescription: "Number of workshop-admin approvals required before executing an action. The requestor cannot approve their own request.",
				Optional:            true,
			},
			"exclude_api_keys": schema.BoolAttribute{
				Description:         "If true, API key requests bypass MPA and execute immediately.",
				MarkdownDescription: "If true, API key requests bypass MPA and execute immediately.",
				Optional:            true,
			},
		},
	}
}

func (r *MPASettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *MPASettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data MPASettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	maxDuration, err := tfStringToDuration(data.MaxDuration)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("max_duration"), "Invalid duration", err.Error())
		return
	}

	b := apipb.SetMultipartyApprovalSettingsRequest_builder{
		Enabled:           tfBoolToPtr(data.Enabled),
		MaxDuration:       maxDuration,
		RequiredApprovers: tfInt64ToUint32Ptr(data.RequiredApprovers),
		ExcludeApiKeys:    tfBoolToPtr(data.ExcludeApiKeys),
	}
	ret, err := r.client.SetMultipartyApprovalSettings(ctx, b.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to set MPA settings: %v", err))
		return
	}
	if ret.GetApprovalRequired() {
		resp.Diagnostics.AddError(
			"MPA approval required",
			fmt.Sprintf("Changing MPA settings requires approval from %d additional admin(s). An approval request has been created on the server; resolve it out-of-band and re-run apply.", ret.GetNumberOfApprovalsNeeded()),
		)
		return
	}

	tflog.Info(ctx, "Created MPA settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, MPASettingsIdentityModel{Id: types.StringValue("mpa_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *MPASettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetMultipartyApprovalSettings(ctx, apipb.GetMultipartyApprovalSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get MPA settings: %v", err))
		return
	}

	data := mpaProtoToModel(ret.GetSettings())
	resp.Diagnostics.Append(resp.Identity.Set(ctx, MPASettingsIdentityModel{Id: types.StringValue("mpa_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *MPASettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state MPASettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Partial update: SetMultipartyApprovalSettings only modifies fields with
	// explicit presence on the request. Compute which fields changed and only
	// include those.
	b := apipb.SetMultipartyApprovalSettingsRequest_builder{}
	any := false
	if !plan.Enabled.Equal(state.Enabled) {
		b.Enabled = tfBoolToPtr(plan.Enabled)
		any = true
	}
	if !plan.MaxDuration.Equal(state.MaxDuration) {
		d, err := tfStringToDuration(plan.MaxDuration)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("max_duration"), "Invalid duration", err.Error())
			return
		}
		b.MaxDuration = d
		any = true
	}
	if !plan.RequiredApprovers.Equal(state.RequiredApprovers) {
		b.RequiredApprovers = tfInt64ToUint32Ptr(plan.RequiredApprovers)
		any = true
	}
	if !plan.ExcludeApiKeys.Equal(state.ExcludeApiKeys) {
		b.ExcludeApiKeys = tfBoolToPtr(plan.ExcludeApiKeys)
		any = true
	}

	if any {
		ret, err := r.client.SetMultipartyApprovalSettings(ctx, b.Build())
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to set MPA settings: %v", err))
			return
		}
		if ret.GetApprovalRequired() {
			// MPA is currently enabled and changing these settings requires
			// approval from additional admins. Terraform cannot wait for
			// asynchronous approval, so surface this as an error.
			resp.Diagnostics.AddError(
				"MPA approval required",
				fmt.Sprintf("Changing MPA settings requires approval from %d additional admin(s). An approval request has been created on the server; resolve it out-of-band and re-run apply.", ret.GetNumberOfApprovalsNeeded()),
			)
			return
		}
		tflog.Info(ctx, "Updated MPA settings")
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, MPASettingsIdentityModel{Id: types.StringValue("mpa_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *MPASettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed MPA settings from Terraform state (server-side configuration unchanged)")
}

func (r *MPASettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &MPASettingsResourceModel{})...)
}

func (r *MPASettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func mpaProtoToModel(s *apipb.MultipartyApprovalSettings) MPASettingsResourceModel {
	if s == nil {
		return MPASettingsResourceModel{}
	}
	return MPASettingsResourceModel{
		Enabled:           types.BoolValue(s.GetEnabled()),
		MaxDuration:       durationToTFString(s.GetMaxDuration()),
		RequiredApprovers: types.Int64Value(int64(s.GetRequiredApprovers())),
		ExcludeApiKeys:    types.BoolValue(s.GetExcludeApiKeys()),
	}
}
