// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

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

var _ resource.Resource = &TagOrderResource{}
var _ resource.ResourceWithConfigure = &TagOrderResource{}
var _ resource.ResourceWithImportState = &TagOrderResource{}
var _ resource.ResourceWithIdentity = &TagOrderResource{}

func NewTagOrderResource() resource.Resource {
	return &TagOrderResource{}
}

// TagOrderResource manages the global, ordered list of enabled tags.
type TagOrderResource struct {
	client svcpb.WorkshopServiceClient
}

type TagOrderIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type TagOrderResourceModel struct {
	Tags types.List `tfsdk:"tags"`
}

func (r *TagOrderResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_tag_order"
}

func (r *TagOrderResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_tag_order resource manages the global, ordered list of enabled tags for Workshop. This is a singleton resource — one per tenant. Order determines precedence (first = highest); when a host has multiple tags, a setting or rule defined in the higher-priority tag wins. A tag that is not in this list is not enabled: it cannot be automatically applied to hosts from group memberships and has no effect. This resource is authoritative — it owns the entire order, so any tag not listed is removed from the order on apply. The initial apply imports the existing order; destroying the resource removes it from state without modifying the server.",
		MarkdownDescription: "The `nps_workshop_tag_order` resource manages the global, ordered list of enabled tags for Workshop. This is a singleton resource — one per tenant. Order determines precedence (first = highest); when a host has multiple tags, a setting or rule defined in the higher-priority tag wins. A tag that is not in this list is **not enabled**: it cannot be automatically applied to hosts from group memberships and has no effect. This resource is authoritative — it owns the entire order, so any tag not listed is removed from the order on apply. The initial apply imports the existing order; destroying the resource removes it from state without modifying the server.",

		Attributes: map[string]schema.Attribute{
			"tags": schema.ListAttribute{
				Description:         "Ordered list of enabled tag names, highest precedence first. Tags not in this list are not enabled and have no effect.",
				MarkdownDescription: "Ordered list of enabled tag names, highest precedence first. Tags not in this list are not enabled and have no effect.",
				Required:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.UniqueValues(),
				},
			},
		},
	}
}

func (r *TagOrderResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// updateOrder pushes the ordered tag list from data to the server.
func (r *TagOrderResource) updateOrder(ctx context.Context, data TagOrderResourceModel, diags *diag.Diagnostics) {
	var tags []string
	diags.Append(data.Tags.ElementsAs(ctx, &tags, false)...)
	if diags.HasError() {
		return
	}
	if tags == nil {
		tags = []string{}
	}

	if _, err := r.client.UpdateTagOrder(ctx, apipb.UpdateTagOrderRequest_builder{
		Tags: tags,
	}.Build()); err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to update tag order: %v", err))
	}
}

func (r *TagOrderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TagOrderResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.updateOrder(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, "Created tag order resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, TagOrderIdentityModel{Id: types.StringValue("tag_order")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TagOrderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetTagOrder(ctx, apipb.GetTagOrderRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get tag order: %v", err))
		return
	}

	tags := ret.GetTags()
	if tags == nil {
		tags = []string{}
	}
	list, d := types.ListValueFrom(ctx, types.StringType, tags)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	data := TagOrderResourceModel{Tags: list}
	resp.Diagnostics.Append(resp.Identity.Set(ctx, TagOrderIdentityModel{Id: types.StringValue("tag_order")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TagOrderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data TagOrderResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.updateOrder(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, "Updated tag order")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, TagOrderIdentityModel{Id: types.StringValue("tag_order")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TagOrderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed tag order from Terraform state (server-side order unchanged)")
}

func (r *TagOrderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &TagOrderResourceModel{Tags: types.ListNull(types.StringType)})...)
}

func (r *TagOrderResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}
