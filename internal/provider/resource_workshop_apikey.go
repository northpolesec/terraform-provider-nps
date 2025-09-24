// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &APIKeyResource{}
var _ resource.ResourceWithImportState = &APIKeyResource{}

func NewAPIKeyResource() resource.Resource {
	return &APIKeyResource{}
}

// APIKeyResource defines the resource implementation.
type APIKeyResource struct {
	client svcpb.WorkshopServiceClient
}

// APIKeyResourceModel describes the resource data model.
type APIKeyResourceModel struct {
	Name        types.String `tfsdk:"name"`
	Permissions types.List   `tfsdk:"permissions"`
	Lifetime    types.Int64  `tfsdk:"lifetime"`
	Secret      types.String `tfsdk:"secret"`
}

func (r *APIKeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_apikey"
}

func (r *APIKeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "APIKey",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "The name for this key",
				Required:            true,
			},
			"permissions": schema.ListAttribute{
				MarkdownDescription: "The permissions for this key",
				Required:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
			},
			"lifetime": schema.Int64Attribute{
				MarkdownDescription: "The lifetime for this key in hours",
				Optional:            true,
			},

			// Computed value, returned from Create
			"secret": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "The key secret",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *APIKeyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
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

func (r *APIKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data APIKeyResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	elements := make([]types.String, 0, len(data.Permissions.Elements()))
	_ = data.Permissions.ElementsAs(ctx, &elements, false)
	perms := make([]string, 0, len(elements))
	for _, e := range elements {
		perms = append(perms, e.ValueString())
	}

	lifetimeHours := time.Duration(data.Lifetime.ValueInt64()) * time.Hour
	if lifetimeHours == 0 {
		lifetimeHours = 24 * 30 * time.Hour
	}

	ckResp, err := r.client.CreateAPIKey(ctx, apipb.CreateAPIKeyRequest_builder{
		Name:        proto.String(data.Name.ValueString()),
		Permissions: perms,
		Lifetime:    durationpb.New(lifetimeHours),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create API key: %v", err))
		return
	}
	if ckResp.GetSecret() == "" {
		resp.Diagnostics.AddError("Client Error", "Failed to get secret for new rule")
		return
	}

	data.Secret = types.StringValue(ckResp.GetSecret())
	tflog.Info(ctx, fmt.Sprintf("Created API key: %q", data.Secret))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data APIKeyResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	ret, err := r.client.ListAPIKeys(ctx, apipb.ListAPIKeysRequest_builder{
		Filter:   proto.String("name = \"" + data.Name.ValueString() + "\""),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list API keys: %v", err))
		return
	}
	if len(ret.GetKeys()) == 0 {
		tflog.Info(ctx, fmt.Sprintf("API key %q not found", data.Name.ValueString()))
		resp.State.RemoveResource(ctx)
		return
	}

	key := ret.GetKeys()[0]
	data.Name = types.StringValue(key.GetName())
	data.Permissions, _ = types.ListValueFrom(ctx, types.StringType, key.GetPermissions())

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data APIKeyResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data APIKeyResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteAPIKey(ctx, apipb.DeleteAPIKeyRequest_builder{
		Name: proto.String(data.Name.ValueString()),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete API key: %v", err))
		return
	}
}

func (r *APIKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
