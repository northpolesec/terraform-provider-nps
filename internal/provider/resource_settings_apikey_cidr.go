// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"net"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
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

var _ resource.Resource = &APIKeyCIDRSettingsResource{}
var _ resource.ResourceWithConfigure = &APIKeyCIDRSettingsResource{}
var _ resource.ResourceWithImportState = &APIKeyCIDRSettingsResource{}
var _ resource.ResourceWithIdentity = &APIKeyCIDRSettingsResource{}

func NewAPIKeyCIDRSettingsResource() resource.Resource {
	return &APIKeyCIDRSettingsResource{}
}

type APIKeyCIDRSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type APIKeyCIDRSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type APIKeyCIDRSettingsResourceModel struct {
	Enabled      types.Bool `tfsdk:"enabled"`
	AllowedCidrs types.List `tfsdk:"allowed_cidrs"`
}

func (r *APIKeyCIDRSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_apikey_cidr"
}

func (r *APIKeyCIDRSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_apikey_cidr resource manages the CIDR restrictions applied to API key requests for Workshop. This is a singleton resource — one per tenant, not per key. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",
		MarkdownDescription: "The `nps_workshop_settings_apikey_cidr` resource manages the CIDR restrictions applied to API key requests for Workshop. This is a singleton resource — one per tenant, not per key. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",

		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether CIDR restrictions are enforced for API key requests. Kept separate from `allowed_cidrs` so an allowlist can be staged without being active, or enforcement can be paused without losing the configured ranges.",
			},
			"allowed_cidrs": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "CIDR ranges allowed to use API keys (e.g. `10.0.0.0/8`). Empty means unrestricted. Maximum 25 entries.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(25),
					listvalidator.ValueStringsAre(cidrValidator{}),
				},
			},
		},
	}
}

func (r *APIKeyCIDRSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *APIKeyCIDRSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data APIKeyCIDRSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Created API key CIDR settings resource")
	resp.Diagnostics.Append(resp.Identity.Set(ctx, APIKeyCIDRSettingsIdentityModel{Id: types.StringValue("apikey_cidr_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyCIDRSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetAPIKeyCIDRSettings(ctx, apipb.GetAPIKeyCIDRSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get API key CIDR settings: %v", err))
		return
	}

	data, d := apikeyCIDRProtoToModel(ctx, ret.GetSettings())
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, APIKeyCIDRSettingsIdentityModel{Id: types.StringValue("apikey_cidr_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyCIDRSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan APIKeyCIDRSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updated API key CIDR settings")
	resp.Diagnostics.Append(resp.Identity.Set(ctx, APIKeyCIDRSettingsIdentityModel{Id: types.StringValue("apikey_cidr_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *APIKeyCIDRSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed API key CIDR settings from Terraform state (server-side configuration unchanged)")
}

func (r *APIKeyCIDRSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &APIKeyCIDRSettingsResourceModel{
		AllowedCidrs: types.ListNull(types.StringType),
	})...)
}

func (r *APIKeyCIDRSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

// set pushes the full settings message. SetAPIKeyCIDRSettings replaces the whole
// APIKeyCIDRSettings message (no field-level presence), so both Create and Update
// always send the complete plan.
func (r *APIKeyCIDRSettingsResource) set(ctx context.Context, m *APIKeyCIDRSettingsResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	var cidrs []string
	if !m.AllowedCidrs.IsNull() && !m.AllowedCidrs.IsUnknown() {
		diags.Append(m.AllowedCidrs.ElementsAs(ctx, &cidrs, false)...)
		if diags.HasError() {
			return diags
		}
	}

	settings := apipb.APIKeyCIDRSettings_builder{
		Enabled:      m.Enabled.ValueBool(),
		AllowedCidrs: cidrs,
	}.Build()

	if _, err := r.client.SetAPIKeyCIDRSettings(ctx, apipb.SetAPIKeyCIDRSettingsRequest_builder{Settings: settings}.Build()); err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to set API key CIDR settings: %v", err))
	}
	return diags
}

func apikeyCIDRProtoToModel(ctx context.Context, s *apipb.APIKeyCIDRSettings) (APIKeyCIDRSettingsResourceModel, diag.Diagnostics) {
	if s == nil {
		return APIKeyCIDRSettingsResourceModel{AllowedCidrs: types.ListNull(types.StringType)}, nil
	}

	cidrs := types.ListNull(types.StringType)
	var diags diag.Diagnostics
	if len(s.GetAllowedCidrs()) > 0 {
		cidrs, diags = types.ListValueFrom(ctx, types.StringType, s.GetAllowedCidrs())
	}

	return APIKeyCIDRSettingsResourceModel{
		Enabled:      types.BoolValue(s.GetEnabled()),
		AllowedCidrs: cidrs,
	}, diags
}

// cidrValidator rejects strings that are not valid CIDR notation, surfacing the
// error at plan time rather than as an opaque server rejection on apply.
type cidrValidator struct{}

func (cidrValidator) Description(context.Context) string {
	return "value must be valid CIDR notation (e.g. 10.0.0.0/8)"
}

func (v cidrValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (cidrValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, _, err := net.ParseCIDR(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid CIDR", fmt.Sprintf("%q is not valid CIDR notation: %v", req.ConfigValue.ValueString(), err))
	}
}
