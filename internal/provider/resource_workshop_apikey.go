// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
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
var _ resource.ResourceWithIdentity = &APIKeyResource{}
var _ list.ListResource = &APIKeyResource{}
var _ list.ListResourceWithConfigure = &APIKeyResource{}

func NewAPIKeyResource() resource.Resource {
	return &APIKeyResource{}
}

// APIKeyResource defines the resource implementation.
type APIKeyResource struct {
	client svcpb.WorkshopServiceClient
}

// APIKeyIdentityModel describes the identity data model.
type APIKeyIdentityModel struct {
	Name types.String `tfsdk:"name"`
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
		MarkdownDescription: "The `nps_workshop_apikey` resource manages API keys.",

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

	// Set the identity
	resp.Diagnostics.Append(resp.Identity.Set(ctx, APIKeyIdentityModel{Name: data.Name})...)

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

	// Set the identity
	resp.Diagnostics.Append(resp.Identity.Set(ctx, APIKeyIdentityModel{Name: data.Name})...)

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

func (r *APIKeyResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"name": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func NewAPIKeyListResource() list.ListResource {
	return &APIKeyResource{}
}

func (r *APIKeyResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "List all API keys in the Workshop instance.",
		Attributes:  map[string]listschema.Attribute{},
	}
}

func (r *APIKeyResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	stream.Results = func(push func(list.ListResult) bool) {
		ret, err := r.client.ListAPIKeys(ctx, apipb.ListAPIKeysRequest_builder{}.Build())
		if err != nil {
			result := req.NewListResult(ctx)
			result.Diagnostics.AddError("Client Error", "Failed to list API keys: "+err.Error())
			push(result)
			return
		}

		for _, key := range ret.GetKeys() {
			result := req.NewListResult(ctx)
			result.DisplayName = key.GetName()

			result.Diagnostics.Append(result.Identity.Set(ctx, APIKeyIdentityModel{
				Name: types.StringValue(key.GetName()),
			})...)

			if req.IncludeResource {
				permissions, _ := types.ListValueFrom(ctx, types.StringType, key.GetPermissions())
				result.Diagnostics.Append(result.Resource.Set(ctx, APIKeyResourceModel{
					Name:        types.StringValue(key.GetName()),
					Permissions: permissions,
				})...)
			}

			if !push(result) {
				return
			}
		}
	}
}
