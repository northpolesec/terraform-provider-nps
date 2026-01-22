// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/protobuf/proto"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &TagResource{}
var _ resource.ResourceWithImportState = &TagResource{}
var _ resource.ResourceWithIdentity = &TagResource{}
var _ list.ListResource = &TagResource{}
var _ list.ListResourceWithConfigure = &TagResource{}

func NewTagResource() resource.Resource {
	return &TagResource{}
}

func NewTagListResource() list.ListResource {
	return &TagResource{}
}

// TagResource defines the resource implementation.
type TagResource struct {
	client svcpb.WorkshopServiceClient
}

// TagIdentityModel describes the identity data model.
type TagIdentityModel struct {
	Name types.String `tfsdk:"name"`
}

// TagResourceModel describes the resource data model.
type TagResourceModel struct {
	Name types.String `tfsdk:"name"`
}

func (r *TagResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_tag"
}

func (r *TagResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_tag resource manages tags.",
		MarkdownDescription: "The `nps_workshop_tag` resource manages tags.",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description:         "The name for this tag",
				MarkdownDescription: "The name for this tag",
				Required:            true,
			},
		},
	}
}

func (r *TagResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *TagResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TagResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.CreateTag(ctx, apipb.CreateTagRequest_builder{
		Tag: proto.String(data.Name.ValueString()),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create tag: %v", err))
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Created tag: %q", data.Name))

	resp.Diagnostics.Append(resp.Identity.Set(ctx, TagIdentityModel{Name: data.Name})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TagResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data TagResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ret, err := r.client.ListTags(ctx, apipb.ListTagsRequest_builder{
		Filter:   proto.String("tag = \"" + data.Name.ValueString() + "\""),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list tags: %v", err))
		return
	}
	if len(ret.GetTags()) == 0 {
		tflog.Info(ctx, fmt.Sprintf("Tag %q not found", data.Name.ValueString()))
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, TagIdentityModel{Name: data.Name})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TagResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data TagResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TagResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data TagResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteTag(ctx, apipb.DeleteTagRequest_builder{
		Tag: proto.String(data.Name.ValueString()),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete tag: %v", err))
		return
	}
}

func (r *TagResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}

func (r *TagResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"name": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func (r *TagResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "List all tags in the Workshop instance.",
		Attributes:  map[string]listschema.Attribute{},
	}
}

func (r *TagResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	stream.Results = func(push func(list.ListResult) bool) {
		ret, err := r.client.ListTags(ctx, apipb.ListTagsRequest_builder{}.Build())
		if err != nil {
			result := req.NewListResult(ctx)
			result.Diagnostics.AddError("Client Error", "Failed to list tags: "+err.Error())
			push(result)
			return
		}

		for _, tagStats := range ret.GetTags() {
			tagName := tagStats.GetTag()
			result := req.NewListResult(ctx)
			result.DisplayName = tagName

			result.Diagnostics.Append(result.Identity.Set(ctx, TagIdentityModel{
				Name: types.StringValue(tagName),
			})...)

			if req.IncludeResource {
				result.Diagnostics.Append(result.Resource.Set(ctx, TagResourceModel{
					Name: types.StringValue(tagName),
				})...)
			}

			if !push(result) {
				return
			}
		}
	}
}
