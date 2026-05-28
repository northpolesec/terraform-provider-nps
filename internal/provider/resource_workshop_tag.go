// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/diag"
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

// errGroupNotFound is returned when no group matches a supplied identifier.
var errGroupNotFound = errors.New("group not found")

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
	Name        types.String `tfsdk:"name"`
	GroupNames  types.Set    `tfsdk:"group_names"`
	GroupIdpIds types.Set    `tfsdk:"group_idp_ids"`
}

// groupRef identifies a directory group by one of its user-facing
// identifiers. field is either "name" or "idp_id".
type groupRef struct {
	field string
	value string
}

func (g groupRef) key() string { return g.field + "=" + g.value }

func (r *TagResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_tag"
}

func (r *TagResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_tag resource manages tags and their assignment to directory groups.",
		MarkdownDescription: "The `nps_workshop_tag` resource manages tags and their assignment to directory groups.",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description:         "The name for this tag",
				MarkdownDescription: "The name for this tag",
				Required:            true,
			},
			"group_names": schema.SetAttribute{
				Description:         "Names of directory groups this tag should be assigned to. Workshop manages group tags by internal ID; the provider resolves each name via ListGroups and merges this tag into the group's existing tags. A name that matches zero or more than one group is an error.",
				MarkdownDescription: "Names of directory groups this tag should be assigned to. Workshop manages group tags by internal ID; the provider resolves each name via `ListGroups` and merges this tag into the group's existing tags. A name that matches zero or more than one group is an error.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"group_idp_ids": schema.SetAttribute{
				Description:         "Identity-provider IDs of directory groups this tag should be assigned to. Resolved and merged the same way as group_names.",
				MarkdownDescription: "Identity-provider IDs of directory groups this tag should be assigned to. Resolved and merged the same way as `group_names`.",
				Optional:            true,
				ElementType:         types.StringType,
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

// modelGroupRefs collects the group references declared in the model.
func modelGroupRefs(ctx context.Context, data TagResourceModel, diags *diag.Diagnostics) []groupRef {
	var names, idpIDs []string
	if !data.GroupNames.IsNull() && !data.GroupNames.IsUnknown() {
		diags.Append(data.GroupNames.ElementsAs(ctx, &names, false)...)
	}
	if !data.GroupIdpIds.IsNull() && !data.GroupIdpIds.IsUnknown() {
		diags.Append(data.GroupIdpIds.ElementsAs(ctx, &idpIDs, false)...)
	}

	refs := make([]groupRef, 0, len(names)+len(idpIDs))
	for _, n := range names {
		refs = append(refs, groupRef{field: "name", value: n})
	}
	for _, id := range idpIDs {
		refs = append(refs, groupRef{field: "idp_id", value: id})
	}
	return refs
}

// resolveGroup looks up the single group matching ref. It returns
// errGroupNotFound if no group matches, and an error if more than one does.
func (r *TagResource) resolveGroup(ctx context.Context, ref groupRef) (*apipb.Group, error) {
	filter := fmt.Sprintf("%s = %q", ref.field, ref.value)
	ret, err := r.client.ListGroups(ctx, apipb.ListGroupsRequest_builder{
		Filter: proto.String(filter),
	}.Build())
	if err != nil {
		return nil, fmt.Errorf("failed to list groups with filter %q: %w", filter, err)
	}

	// Filter to exact matches defensively, in case the server treats the
	// filter as a substring or case-insensitive match.
	var matches []*apipb.Group
	for _, g := range ret.GetGroups() {
		switch ref.field {
		case "name":
			if g.GetName() == ref.value {
				matches = append(matches, g)
			}
		case "idp_id":
			if g.GetIdpId() == ref.value {
				matches = append(matches, g)
			}
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("%w: no group with %s %q", errGroupNotFound, ref.field, ref.value)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("%d groups match %s %q; cannot disambiguate", len(matches), ref.field, ref.value)
	}
}

// setGroupTag adds (present) or removes (!present) tag from the group,
// preserving the group's other attributes. It is a no-op if the group is
// already in the desired state.
func (r *TagResource) setGroupTag(ctx context.Context, g *apipb.Group, tag string, present bool) error {
	has := slices.Contains(g.GetTags(), tag)
	if has == present {
		return nil
	}

	newTags := slices.Clone(g.GetTags())
	if present {
		newTags = append(newTags, tag)
	} else {
		newTags = slices.DeleteFunc(newTags, func(t string) bool { return t == tag })
	}

	// Echo the existing name and description back so UpdateGroup only mutates
	// the tag list.
	_, err := r.client.UpdateGroup(ctx, apipb.UpdateGroupRequest_builder{
		Id:          proto.String(g.GetId()),
		Name:        proto.String(g.GetName()),
		Description: proto.String(g.GetDescription()),
		Tags:        newTags,
	}.Build())
	return err
}

// applyGroupTag resolves ref and sets the tag's presence on it, recording any
// failure in diags.
func (r *TagResource) applyGroupTag(ctx context.Context, ref groupRef, tag string, present bool, diags *diag.Diagnostics) {
	g, err := r.resolveGroup(ctx, ref)
	if err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to resolve group %s %q: %v", ref.field, ref.value, err))
		return
	}
	if err := r.setGroupTag(ctx, g, tag, present); err != nil {
		verb := "assign tag to"
		if !present {
			verb = "remove tag from"
		}
		diags.AddError("Client Error", fmt.Sprintf("Failed to %s group %s %q: %v", verb, ref.field, ref.value, err))
	}
}

func (r *TagResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TagResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	refs := modelGroupRefs(ctx, data, &resp.Diagnostics)
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

	for _, ref := range refs {
		r.applyGroupTag(ctx, ref, data.Name.ValueString(), true, &resp.Diagnostics)
	}
	if resp.Diagnostics.HasError() {
		return
	}

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

	// Reconcile group assignments: keep only the groups that still exist and
	// still carry this tag. Anything else has drifted and will be re-applied
	// on the next plan.
	refs := modelGroupRefs(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tag := data.Name.ValueString()
	var names, idpIDs []string
	for _, ref := range refs {
		g, err := r.resolveGroup(ctx, ref)
		if errors.Is(err, errGroupNotFound) {
			continue
		}
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to resolve group %s %q: %v", ref.field, ref.value, err))
			return
		}
		if !slices.Contains(g.GetTags(), tag) {
			continue
		}
		switch ref.field {
		case "name":
			names = append(names, ref.value)
		case "idp_id":
			idpIDs = append(idpIDs, ref.value)
		}
	}

	data.GroupNames = stringSetOrNull(ctx, names, &resp.Diagnostics)
	data.GroupIdpIds = stringSetOrNull(ctx, idpIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, TagIdentityModel{Name: data.Name})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// stringSetOrNull builds a set from values, returning a null set (rather than
// an empty one) when there are no values so it matches an unset attribute.
func stringSetOrNull(ctx context.Context, values []string, diags *diag.Diagnostics) types.Set {
	if len(values) == 0 {
		return types.SetNull(types.StringType)
	}
	set, d := types.SetValueFrom(ctx, types.StringType, values)
	diags.Append(d...)
	return set
}

func (r *TagResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state TagResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planRefs := modelGroupRefs(ctx, plan, &resp.Diagnostics)
	stateRefs := modelGroupRefs(ctx, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	planSet := make(map[string]groupRef, len(planRefs))
	for _, ref := range planRefs {
		planSet[ref.key()] = ref
	}
	stateSet := make(map[string]groupRef, len(stateRefs))
	for _, ref := range stateRefs {
		stateSet[ref.key()] = ref
	}

	tag := plan.Name.ValueString()

	// Remove the tag from groups no longer in the plan.
	for k, ref := range stateSet {
		if _, ok := planSet[k]; !ok {
			r.applyGroupTag(ctx, ref, tag, false, &resp.Diagnostics)
		}
	}
	// Add the tag to groups newly in the plan.
	for k, ref := range planSet {
		if _, ok := stateSet[k]; !ok {
			r.applyGroupTag(ctx, ref, tag, true, &resp.Diagnostics)
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TagResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data TagResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Unassign the tag from its groups before deleting it so groups aren't
	// left referencing a tag that no longer exists.
	refs := modelGroupRefs(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tag := data.Name.ValueString()
	for _, ref := range refs {
		g, err := r.resolveGroup(ctx, ref)
		if errors.Is(err, errGroupNotFound) {
			// Group is already gone; nothing to unassign.
			continue
		}
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to resolve group %s %q: %v", ref.field, ref.value, err))
			return
		}
		if err := r.setGroupTag(ctx, g, tag, false); err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to remove tag from group %s %q: %v", ref.field, ref.value, err))
			return
		}
	}

	_, err := r.client.DeleteTag(ctx, apipb.DeleteTagRequest_builder{
		Tag: proto.String(tag),
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
					Name:        types.StringValue(tagName),
					GroupNames:  types.SetNull(types.StringType),
					GroupIdpIds: types.SetNull(types.StringType),
				})...)
			}

			if !push(result) {
				return
			}
		}
	}
}
