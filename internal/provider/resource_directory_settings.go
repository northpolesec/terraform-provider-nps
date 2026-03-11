// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &DirectorySettingsResource{}
var _ resource.ResourceWithConfigure = &DirectorySettingsResource{}
var _ resource.ResourceWithImportState = &DirectorySettingsResource{}
var _ resource.ResourceWithIdentity = &DirectorySettingsResource{}
var _ resource.ResourceWithConfigValidators = &DirectorySettingsResource{}

func NewDirectorySettingsResource() resource.Resource {
	return &DirectorySettingsResource{}
}

// DirectorySettingsResource defines the resource implementation.
type DirectorySettingsResource struct {
	client svcpb.WorkshopServiceClient
}

// DirectorySettingsIdentityModel describes the identity data model.
type DirectorySettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

// DirectorySettingsGroupModel describes a group in the directory sync group filter.
type DirectorySettingsGroupModel struct {
	Id   types.String `tfsdk:"id"`
	Tags types.List   `tfsdk:"tags"`
}

// DirectorySettingsResourceModel describes the resource data model.
type DirectorySettingsResourceModel struct {
	DirectoryType            types.String `tfsdk:"directory_type"`
	DirectorySyncGroupFilter types.List   `tfsdk:"directory_sync_group_filter"`
}

var groupFilterObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"id":   types.StringType,
		"tags": types.ListType{ElemType: types.StringType},
	},
}

func (r *DirectorySettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_directory_settings"
}

func (r *DirectorySettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_directory_settings resource manages directory settings for Workshop. This is a singleton resource — one per tenant.",
		MarkdownDescription: "The `nps_workshop_directory_settings` resource manages directory settings for Workshop. This is a singleton resource — one per tenant.",

		Attributes: map[string]schema.Attribute{
			"directory_type": schema.StringAttribute{
				Description:         "The directory type. Must be one of: DIRECTORY_TYPE_DSYNC, DIRECTORY_TYPE_LOCAL.",
				MarkdownDescription: "The directory type. Must be one of: `DIRECTORY_TYPE_DSYNC`, `DIRECTORY_TYPE_LOCAL`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"DIRECTORY_TYPE_DSYNC",
						"DIRECTORY_TYPE_LOCAL",
					),
				},
			},
		},

		Blocks: map[string]schema.Block{
			"directory_sync_group_filter": schema.ListNestedBlock{
				Description:         "The directory sync group filter. Only applicable when directory_type is DIRECTORY_TYPE_DSYNC.",
				MarkdownDescription: "The directory sync group filter. Only applicable when `directory_type` is `DIRECTORY_TYPE_DSYNC`.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description:         "The group ID.",
							MarkdownDescription: "The group ID.",
							Required:            true,
						},
						"tags": schema.ListAttribute{
							Description:         "The tags associated with this group.",
							MarkdownDescription: "The tags associated with this group.",
							Required:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
		},
	}
}

func (r *DirectorySettingsResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		utils.ConfigValidatorFunc("Validate directory_sync_group_filter is only set for DSYNC", func(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
			var data DirectorySettingsResourceModel
			resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
			if resp.Diagnostics.HasError() {
				return
			}

			if data.DirectoryType.ValueString() == "DIRECTORY_TYPE_LOCAL" && len(data.DirectorySyncGroupFilter.Elements()) > 0 {
				resp.Diagnostics.AddError(
					"Invalid configuration",
					"directory_sync_group_filter can only be set when directory_type is DIRECTORY_TYPE_DSYNC",
				)
			}
		}),
	}
}

func (r *DirectorySettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DirectorySettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DirectorySettingsResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Singleton: Create calls UpdateDirectorySettings
	dirType := apipb.DirectoryType(apipb.DirectoryType_value[data.DirectoryType.ValueString()])

	updateReq := apipb.UpdateDirectorySettingsRequest_builder{
		Type:                     dirType.Enum(),
		DirectorySyncGroupFilter: groupsModelToProto(ctx, data.DirectorySyncGroupFilter, &resp.Diagnostics),
	}.Build()

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.UpdateDirectorySettings(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update directory settings: %v", err))
		return
	}

	tflog.Info(ctx, "Created directory settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, DirectorySettingsIdentityModel{Id: types.StringValue("directory_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DirectorySettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DirectorySettingsResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ret, err := r.client.GetDirectorySettings(ctx, apipb.GetDirectorySettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get directory settings: %v", err))
		return
	}

	data.DirectoryType = types.StringValue(ret.GetType().String())
	data.DirectorySyncGroupFilter = groupsProtoToModel(ctx, ret.GetDirectorySyncGroupFilter(), &resp.Diagnostics)

	resp.Diagnostics.Append(resp.Identity.Set(ctx, DirectorySettingsIdentityModel{Id: types.StringValue("directory_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DirectorySettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data DirectorySettingsResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dirType := apipb.DirectoryType(apipb.DirectoryType_value[data.DirectoryType.ValueString()])

	updateReq := apipb.UpdateDirectorySettingsRequest_builder{
		Type:                     dirType.Enum(),
		DirectorySyncGroupFilter: groupsModelToProto(ctx, data.DirectorySyncGroupFilter, &resp.Diagnostics),
	}.Build()

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.UpdateDirectorySettings(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update directory settings: %v", err))
		return
	}

	tflog.Info(ctx, "Updated directory settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, DirectorySettingsIdentityModel{Id: types.StringValue("directory_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DirectorySettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Singleton: reset to LOCAL with no group filter
	dirType := apipb.DirectoryType_DIRECTORY_TYPE_LOCAL

	updateReq := apipb.UpdateDirectorySettingsRequest_builder{
		Type: dirType.Enum(),
	}.Build()

	_, err := r.client.UpdateDirectorySettings(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to reset directory settings: %v", err))
		return
	}

	tflog.Info(ctx, "Deleted (reset) directory settings resource")
}

func (r *DirectorySettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Singleton: any ID is accepted, Read will fetch current state.
	// We just need to set some initial state so Read can proceed.
	// Set directory_type to a placeholder; Read will overwrite it.
	resp.Diagnostics.Append(resp.State.Set(ctx, &DirectorySettingsResourceModel{
		DirectoryType:            types.StringValue("DIRECTORY_TYPE_UNSPECIFIED"),
		DirectorySyncGroupFilter: types.ListValueMust(groupFilterObjectType, []attr.Value{}),
	})...)
}

func (r *DirectorySettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

// groupsModelToProto converts the Terraform list model to a proto DirectorySyncGroupFilter.
func groupsModelToProto(ctx context.Context, list types.List, diags *diag.Diagnostics) *apipb.DirectorySyncGroupFilter {
	if list.IsNull() || list.IsUnknown() || len(list.Elements()) == 0 {
		return nil
	}

	var groups []DirectorySettingsGroupModel
	diags.Append(list.ElementsAs(ctx, &groups, false)...)
	if diags.HasError() {
		return nil
	}

	protoGroups := make([]*apipb.DirectorySyncGroupFilter_Group, len(groups))
	for i, g := range groups {
		var tags []string
		diags.Append(g.Tags.ElementsAs(ctx, &tags, false)...)

		protoGroups[i] = apipb.DirectorySyncGroupFilter_Group_builder{
			Id:   g.Id.ValueString(),
			Tags: tags,
		}.Build()
	}

	return apipb.DirectorySyncGroupFilter_builder{
		Groups: protoGroups,
	}.Build()
}

// groupsProtoToModel converts a proto DirectorySyncGroupFilter to the Terraform list model.
func groupsProtoToModel(ctx context.Context, filter *apipb.DirectorySyncGroupFilter, diags *diag.Diagnostics) types.List {
	if filter == nil || len(filter.GetGroups()) == 0 {
		return types.ListValueMust(groupFilterObjectType, []attr.Value{})
	}

	groups := filter.GetGroups()
	groupValues := make([]attr.Value, len(groups))

	for i, g := range groups {
		tagsVal, d := types.ListValueFrom(ctx, types.StringType, g.GetTags())
		diags.Append(d...)

		obj, d := types.ObjectValue(groupFilterObjectType.AttrTypes, map[string]attr.Value{
			"id":   types.StringValue(g.GetId()),
			"tags": tagsVal,
		})
		diags.Append(d...)
		groupValues[i] = obj
	}

	result, d := types.ListValue(groupFilterObjectType, groupValues)
	diags.Append(d...)
	return result
}
