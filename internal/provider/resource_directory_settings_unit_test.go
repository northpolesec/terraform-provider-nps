// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestDirectorySettingsDeleteIsStateOnly(t *testing.T) {
	var resp resource.DeleteResponse
	(&DirectorySettingsResource{}).Delete(context.Background(), resource.DeleteRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("state-only delete returned diagnostics: %v", resp.Diagnostics)
	}
}

func TestGroupsModelToProto_NullList(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	result := groupsModelToProto(ctx, types.ListNull(groupFilterObjectType), &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if result != nil {
		t.Fatal("expected nil for null list")
	}
}

func TestGroupsModelToProto_EmptyList(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	emptyList := types.ListValueMust(groupFilterObjectType, []attr.Value{})
	result := groupsModelToProto(ctx, emptyList, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if result != nil {
		t.Fatal("expected nil for empty list")
	}
}

func TestGroupsModelToProto_WithGroups(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	tags1, _ := types.ListValueFrom(ctx, types.StringType, []string{"tag-a", "tag-b"})
	tags2, _ := types.ListValueFrom(ctx, types.StringType, []string{"tag-c"})

	group1, _ := types.ObjectValue(groupFilterObjectType.AttrTypes, map[string]attr.Value{
		"id":   types.StringValue("g1"),
		"tags": tags1,
	})
	group2, _ := types.ObjectValue(groupFilterObjectType.AttrTypes, map[string]attr.Value{
		"id":   types.StringValue("g2"),
		"tags": tags2,
	})

	list := types.ListValueMust(groupFilterObjectType, []attr.Value{group1, group2})
	result := groupsModelToProto(ctx, list, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	groups := result.GetGroups()
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].GetId() != "g1" {
		t.Errorf("expected group id 'g1', got %q", groups[0].GetId())
	}
	if len(groups[0].GetTags()) != 2 || groups[0].GetTags()[0] != "tag-a" || groups[0].GetTags()[1] != "tag-b" {
		t.Errorf("unexpected tags for group 0: %v", groups[0].GetTags())
	}
	if groups[1].GetId() != "g2" {
		t.Errorf("expected group id 'g2', got %q", groups[1].GetId())
	}
	if len(groups[1].GetTags()) != 1 || groups[1].GetTags()[0] != "tag-c" {
		t.Errorf("unexpected tags for group 1: %v", groups[1].GetTags())
	}
}

func TestGroupsModelToProto_InvalidTags(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	// Create a group with tags of the wrong element type (Int64 instead of String)
	badTags, _ := types.ListValueFrom(ctx, types.Int64Type, []int64{1, 2})
	group, _ := types.ObjectValue(
		map[string]attr.Type{
			"id":   types.StringType,
			"tags": types.ListType{ElemType: types.Int64Type},
		},
		map[string]attr.Value{
			"id":   types.StringValue("bad-group"),
			"tags": badTags,
		},
	)

	list, _ := types.ListValue(types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"id":   types.StringType,
			"tags": types.ListType{ElemType: types.Int64Type},
		},
	}, []attr.Value{group})

	result := groupsModelToProto(ctx, list, &diags)
	if !diags.HasError() {
		t.Fatal("expected diagnostics error for invalid tags")
	}
	if result != nil {
		t.Fatal("expected nil result on error")
	}
}

func TestGroupsProtoToModel_Nil(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	result := groupsProtoToModel(ctx, nil, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(result.Elements()) != 0 {
		t.Fatal("expected empty list for nil filter")
	}
}

func TestGroupsProtoToModel_EmptyGroups(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	filter := apipb.DirectorySyncGroupFilter_builder{
		Groups: []*apipb.DirectorySyncGroupFilter_Group{},
	}.Build()

	result := groupsProtoToModel(ctx, filter, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(result.Elements()) != 0 {
		t.Fatal("expected empty list for empty groups")
	}
}

func TestGroupsProtoToModel_WithGroups(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	filter := apipb.DirectorySyncGroupFilter_builder{
		Groups: []*apipb.DirectorySyncGroupFilter_Group{
			apipb.DirectorySyncGroupFilter_Group_builder{
				Id:   "g1",
				Tags: []string{"tag-a", "tag-b"},
			}.Build(),
			apipb.DirectorySyncGroupFilter_Group_builder{
				Id:   "g2",
				Tags: []string{"tag-c"},
			}.Build(),
		},
	}.Build()

	result := groupsProtoToModel(ctx, filter, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	elements := result.Elements()
	if len(elements) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(elements))
	}

	// Verify roundtrip: convert back to proto and check
	roundtripped := groupsModelToProto(ctx, result, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics on roundtrip: %v", diags)
	}

	groups := roundtripped.GetGroups()
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups after roundtrip, got %d", len(groups))
	}
	if groups[0].GetId() != "g1" {
		t.Errorf("expected 'g1', got %q", groups[0].GetId())
	}
	if len(groups[0].GetTags()) != 2 || groups[0].GetTags()[0] != "tag-a" || groups[0].GetTags()[1] != "tag-b" {
		t.Errorf("unexpected tags after roundtrip: %v", groups[0].GetTags())
	}
	if groups[1].GetId() != "g2" {
		t.Errorf("expected 'g2', got %q", groups[1].GetId())
	}
	if len(groups[1].GetTags()) != 1 || groups[1].GetTags()[0] != "tag-c" {
		t.Errorf("unexpected tags after roundtrip: %v", groups[1].GetTags())
	}
}

type fakeDirectorySettingsClient struct {
	svcpb.WorkshopServiceClient

	dirType apipb.DirectoryType
}

func (f *fakeDirectorySettingsClient) GetDirectorySettings(ctx context.Context, in *apipb.GetDirectorySettingsRequest, _ ...grpc.CallOption) (*apipb.GetDirectorySettingsResponse, error) {
	return apipb.GetDirectorySettingsResponse_builder{Type: f.dirType.Enum()}.Build(), nil
}

// callDirectorySettingsRead drives Read with the prior state the framework
// would normally pre-populate.
func callDirectorySettingsRead(t *testing.T, r *DirectorySettingsResource, prior DirectorySettingsResourceModel) DirectorySettingsResourceModel {
	t.Helper()
	ctx := context.Background()

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	var iResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)

	req := resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema}}
	if diags := req.State.Set(ctx, prior); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	resp := &resource.ReadResponse{
		State:    tfsdk.State{Schema: sResp.Schema},
		Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
	}
	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}

	var got DirectorySettingsResourceModel
	if diags := resp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("reading final state: %v", diags)
	}
	return got
}

// TestDirectorySettingsReadKeepsPriorOnUnspecified is the regression test for a
// Read that wrote DIRECTORY_TYPE_UNSPECIFIED into state for a tenant with no
// stored directory type. The schema's own OneOf validator rejects that value,
// so the next plan failed on state the provider itself had written.
func TestDirectorySettingsReadKeepsPriorOnUnspecified(t *testing.T) {
	prior := DirectorySettingsResourceModel{
		DirectoryType:            types.StringValue("DIRECTORY_TYPE_LOCAL"),
		DirectorySyncGroupFilter: types.ListValueMust(groupFilterObjectType, []attr.Value{}),
	}

	r := &DirectorySettingsResource{client: &fakeDirectorySettingsClient{
		dirType: apipb.DirectoryType_DIRECTORY_TYPE_UNSPECIFIED,
	}}
	if got := callDirectorySettingsRead(t, r, prior); got.DirectoryType.ValueString() != "DIRECTORY_TYPE_LOCAL" {
		t.Errorf("directory_type: got %q, want the prior value", got.DirectoryType.ValueString())
	}

	// A concrete value from the server still wins.
	r = &DirectorySettingsResource{client: &fakeDirectorySettingsClient{
		dirType: apipb.DirectoryType_DIRECTORY_TYPE_DSYNC,
	}}
	if got := callDirectorySettingsRead(t, r, prior); got.DirectoryType.ValueString() != "DIRECTORY_TYPE_DSYNC" {
		t.Errorf("directory_type: got %q, want DIRECTORY_TYPE_DSYNC", got.DirectoryType.ValueString())
	}
}

// TestDirectorySettingsImportPlaceholderIsValid checks the placeholder written
// on import satisfies the schema's own validator, since Read leaves it in place
// for a tenant whose directory type is unset.
func TestDirectorySettingsImportPlaceholderIsValid(t *testing.T) {
	ctx := context.Background()
	r := &DirectorySettingsResource{}

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)

	resp := &resource.ImportStateResponse{State: emptyState(ctx, sResp.Schema)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "directory_settings"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}

	var got DirectorySettingsResourceModel
	if diags := resp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("reading state: %v", diags)
	}

	attribute, ok := sResp.Schema.Attributes["directory_type"].(schema.StringAttribute)
	if !ok {
		t.Fatal("directory_type is not a StringAttribute")
	}
	for _, v := range attribute.Validators {
		vResp := &validator.StringResponse{}
		v.ValidateString(ctx, validator.StringRequest{ConfigValue: got.DirectoryType}, vResp)
		if vResp.Diagnostics.HasError() {
			t.Errorf("import placeholder %q fails the schema validator: %v", got.DirectoryType.ValueString(), vResp.Diagnostics)
		}
	}
}
