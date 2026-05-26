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

var _ resource.Resource = &ExportConfigSettingsResource{}
var _ resource.ResourceWithConfigure = &ExportConfigSettingsResource{}
var _ resource.ResourceWithImportState = &ExportConfigSettingsResource{}
var _ resource.ResourceWithIdentity = &ExportConfigSettingsResource{}

func NewExportConfigSettingsResource() resource.Resource {
	return &ExportConfigSettingsResource{}
}

type ExportConfigSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type ExportConfigSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type ExportConfigSettingsResourceModel struct {
	AuditEventBucketUrl        types.String `tfsdk:"audit_event_bucket_url"`
	ExecutionEventBucketUrl    types.String `tfsdk:"execution_event_bucket_url"`
	FileAccessEventBucketUrl   types.String `tfsdk:"file_access_event_bucket_url"`
	UsbMountEventBucketUrl     types.String `tfsdk:"usb_mount_event_bucket_url"`
	NetworkMountEventBucketUrl types.String `tfsdk:"network_mount_event_bucket_url"`
}

func (r *ExportConfigSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_export_config"
}

func (r *ExportConfigSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_export_config resource manages event-export bucket URLs for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server. Set a bucket URL to the empty string to clear it.",
		MarkdownDescription: "The `nps_workshop_settings_export_config` resource manages event-export bucket URLs for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server. Set a bucket URL to the empty string to clear it.",

		Attributes: map[string]schema.Attribute{
			"audit_event_bucket_url":         exportConfigBucketAttr("The bucket URL for audit event export."),
			"execution_event_bucket_url":     exportConfigBucketAttr("The bucket URL for execution event export."),
			"file_access_event_bucket_url":   exportConfigBucketAttr("The bucket URL for file access event export."),
			"usb_mount_event_bucket_url":     exportConfigBucketAttr("The bucket URL for USB mount event export."),
			"network_mount_event_bucket_url": exportConfigBucketAttr("The bucket URL for network mount event export."),
		},
	}
}

func (r *ExportConfigSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ExportConfigSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ExportConfigSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	b := apipb.UpdateExportConfigRequest_builder{
		AuditEventBucketUrl:        tfStringToPtr(data.AuditEventBucketUrl),
		ExecutionEventBucketUrl:    tfStringToPtr(data.ExecutionEventBucketUrl),
		FileAccessEventBucketUrl:   tfStringToPtr(data.FileAccessEventBucketUrl),
		UsbMountEventBucketUrl:     tfStringToPtr(data.UsbMountEventBucketUrl),
		NetworkMountEventBucketUrl: tfStringToPtr(data.NetworkMountEventBucketUrl),
	}
	if _, err := r.client.UpdateExportConfig(ctx, b.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update export config: %v", err))
		return
	}

	tflog.Info(ctx, "Created export config resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, ExportConfigSettingsIdentityModel{Id: types.StringValue("export_config")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ExportConfigSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetExportConfig(ctx, apipb.GetExportConfigRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get export config: %v", err))
		return
	}

	data := exportConfigProtoToModel(ret)
	resp.Diagnostics.Append(resp.Identity.Set(ctx, ExportConfigSettingsIdentityModel{Id: types.StringValue("export_config")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ExportConfigSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ExportConfigSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Partial update: UpdateExportConfig only modifies fields with explicit
	// presence on the request. An explicit empty string clears a bucket URL.
	// Compute which fields changed and only include those.
	b := apipb.UpdateExportConfigRequest_builder{}
	any := false
	if !plan.AuditEventBucketUrl.Equal(state.AuditEventBucketUrl) {
		b.AuditEventBucketUrl = tfStringToPtr(plan.AuditEventBucketUrl)
		if b.AuditEventBucketUrl == nil {
			empty := ""
			b.AuditEventBucketUrl = &empty
		}
		any = true
	}
	if !plan.ExecutionEventBucketUrl.Equal(state.ExecutionEventBucketUrl) {
		b.ExecutionEventBucketUrl = tfStringToPtr(plan.ExecutionEventBucketUrl)
		if b.ExecutionEventBucketUrl == nil {
			empty := ""
			b.ExecutionEventBucketUrl = &empty
		}
		any = true
	}
	if !plan.FileAccessEventBucketUrl.Equal(state.FileAccessEventBucketUrl) {
		b.FileAccessEventBucketUrl = tfStringToPtr(plan.FileAccessEventBucketUrl)
		if b.FileAccessEventBucketUrl == nil {
			empty := ""
			b.FileAccessEventBucketUrl = &empty
		}
		any = true
	}
	if !plan.UsbMountEventBucketUrl.Equal(state.UsbMountEventBucketUrl) {
		b.UsbMountEventBucketUrl = tfStringToPtr(plan.UsbMountEventBucketUrl)
		if b.UsbMountEventBucketUrl == nil {
			empty := ""
			b.UsbMountEventBucketUrl = &empty
		}
		any = true
	}
	if !plan.NetworkMountEventBucketUrl.Equal(state.NetworkMountEventBucketUrl) {
		b.NetworkMountEventBucketUrl = tfStringToPtr(plan.NetworkMountEventBucketUrl)
		if b.NetworkMountEventBucketUrl == nil {
			empty := ""
			b.NetworkMountEventBucketUrl = &empty
		}
		any = true
	}

	if any {
		if _, err := r.client.UpdateExportConfig(ctx, b.Build()); err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update export config: %v", err))
			return
		}
		tflog.Info(ctx, "Updated export config")
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, ExportConfigSettingsIdentityModel{Id: types.StringValue("export_config")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ExportConfigSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed export config from Terraform state (server-side configuration unchanged)")
}

func (r *ExportConfigSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &ExportConfigSettingsResourceModel{})...)
}

func (r *ExportConfigSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func exportConfigBucketAttr(description string) schema.StringAttribute {
	return schema.StringAttribute{
		Description:         description,
		MarkdownDescription: description,
		Optional:            true,
	}
}

func exportConfigProtoToModel(ret *apipb.GetExportConfigResponse) ExportConfigSettingsResourceModel {
	return ExportConfigSettingsResourceModel{
		AuditEventBucketUrl:        stringPtrToTF(ret.AuditEventBucketUrl),
		ExecutionEventBucketUrl:    stringPtrToTF(ret.ExecutionEventBucketUrl),
		FileAccessEventBucketUrl:   stringPtrToTF(ret.FileAccessEventBucketUrl),
		UsbMountEventBucketUrl:     stringPtrToTF(ret.UsbMountEventBucketUrl),
		NetworkMountEventBucketUrl: stringPtrToTF(ret.NetworkMountEventBucketUrl),
	}
}
