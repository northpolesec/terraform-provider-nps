// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

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
