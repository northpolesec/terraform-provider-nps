// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &SyncAuthSettingsResource{}
var _ resource.ResourceWithConfigure = &SyncAuthSettingsResource{}
var _ resource.ResourceWithImportState = &SyncAuthSettingsResource{}
var _ resource.ResourceWithIdentity = &SyncAuthSettingsResource{}

func NewSyncAuthSettingsResource() resource.Resource {
	return &SyncAuthSettingsResource{}
}

type SyncAuthSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type SyncAuthSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type SyncAuthSettingsResourceModel struct {
	EnableMtlsAuth  types.Bool `tfsdk:"enable_mtls_auth"`
	EnableTokenAuth types.Bool `tfsdk:"enable_token_auth"`
	SyncTokens      types.List `tfsdk:"sync_tokens"`
}

func (r *SyncAuthSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_sync_auth"
}

func (r *SyncAuthSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_sync_auth resource manages the Santa sync authentication settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",
		MarkdownDescription: "The `nps_workshop_settings_sync_auth` resource manages the Santa sync authentication settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",

		Attributes: map[string]schema.Attribute{
			"enable_mtls_auth": schema.BoolAttribute{
				Description:         "Whether to enable mTLS certificate-based authentication.",
				MarkdownDescription: "Whether to enable mTLS certificate-based authentication.",
				Required:            true,
			},
			"enable_token_auth": schema.BoolAttribute{
				Description:         "Whether to enable token-based authentication via the Authorization header.",
				MarkdownDescription: "Whether to enable token-based authentication via the `Authorization` header.",
				Required:            true,
			},
			"sync_tokens": schema.ListAttribute{
				Description:         "List of valid bearer tokens for token-based authentication. Sensitive.",
				MarkdownDescription: "List of valid bearer tokens for token-based authentication. Sensitive.",
				Optional:            true,
				ElementType:         types.StringType,
				Sensitive:           true,
			},
		},
	}
}

func (r *SyncAuthSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SyncAuthSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SyncAuthSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var tokens []string
	if !data.SyncTokens.IsNull() && !data.SyncTokens.IsUnknown() {
		resp.Diagnostics.Append(data.SyncTokens.ElementsAs(ctx, &tokens, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	settings := apipb.SyncAuthSettings_builder{
		EnableMtlsAuth:  data.EnableMtlsAuth.ValueBool(),
		EnableTokenAuth: data.EnableTokenAuth.ValueBool(),
		SyncTokens:      tokens,
	}.Build()

	if _, err := r.client.UpdateSyncAuthSettings(ctx, apipb.UpdateSyncAuthSettingsRequest_builder{SyncAuthSettings: settings}.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update sync auth settings: %v", err))
		return
	}

	tflog.Info(ctx, "Created sync auth settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SyncAuthSettingsIdentityModel{Id: types.StringValue("sync_auth_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SyncAuthSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetSyncAuthSettings(ctx, apipb.GetSyncAuthSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get sync auth settings: %v", err))
		return
	}

	data, d := syncAuthProtoToModel(ctx, ret.GetSyncAuthSettings())
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SyncAuthSettingsIdentityModel{Id: types.StringValue("sync_auth_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SyncAuthSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SyncAuthSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var tokens []string
	if !plan.SyncTokens.IsNull() && !plan.SyncTokens.IsUnknown() {
		resp.Diagnostics.Append(plan.SyncTokens.ElementsAs(ctx, &tokens, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// UpdateSyncAuthSettings replaces the whole SyncAuthSettings message; it
	// is not presence-sensitive, so we always send the full plan.
	settings := apipb.SyncAuthSettings_builder{
		EnableMtlsAuth:  plan.EnableMtlsAuth.ValueBool(),
		EnableTokenAuth: plan.EnableTokenAuth.ValueBool(),
		SyncTokens:      tokens,
	}.Build()

	if _, err := r.client.UpdateSyncAuthSettings(ctx, apipb.UpdateSyncAuthSettingsRequest_builder{SyncAuthSettings: settings}.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update sync auth settings: %v", err))
		return
	}

	tflog.Info(ctx, "Updated sync auth settings")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SyncAuthSettingsIdentityModel{Id: types.StringValue("sync_auth_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SyncAuthSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed sync auth settings from Terraform state (server-side configuration unchanged)")
}

func (r *SyncAuthSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &SyncAuthSettingsResourceModel{
		EnableMtlsAuth:  types.BoolValue(false),
		EnableTokenAuth: types.BoolValue(false),
		SyncTokens:      types.ListNull(types.StringType),
	})...)
}

func (r *SyncAuthSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func syncAuthProtoToModel(ctx context.Context, s *apipb.SyncAuthSettings) (SyncAuthSettingsResourceModel, diag.Diagnostics) {
	if s == nil {
		return SyncAuthSettingsResourceModel{
			EnableMtlsAuth:  types.BoolValue(false),
			EnableTokenAuth: types.BoolValue(false),
			SyncTokens:      types.ListNull(types.StringType),
		}, nil
	}
	tokens, d := types.ListValueFrom(ctx, types.StringType, s.GetSyncTokens())
	if d.HasError() {
		return SyncAuthSettingsResourceModel{}, d
	}
	if len(s.GetSyncTokens()) == 0 {
		tokens = types.ListNull(types.StringType)
	}
	return SyncAuthSettingsResourceModel{
		EnableMtlsAuth:  types.BoolValue(s.GetEnableMtlsAuth()),
		EnableTokenAuth: types.BoolValue(s.GetEnableTokenAuth()),
		SyncTokens:      tokens,
	}, d
}
