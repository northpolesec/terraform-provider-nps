// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// fakeWorkshopClient embeds the full client interface (so it satisfies it) and
// only overrides the rule create/delete RPCs the update path uses. Any other
// call panics, which is what we want for a focused unit test.
type fakeWorkshopClient struct {
	svcpb.WorkshopServiceClient

	createErr error
	deleteErr error
	newID     int64 // returned ruleId on create

	created   bool
	deletedID int64 // 0 means no delete happened (rule IDs are non-zero)
}

func (f *fakeWorkshopClient) CreateRule(ctx context.Context, in *apipb.CreateRuleRequest, _ ...grpc.CallOption) (*apipb.CreateRuleResponse, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = true
	return apipb.CreateRuleResponse_builder{RuleId: proto.String("rule-new")}.Build(), nil
}

func (f *fakeWorkshopClient) DeleteRule(ctx context.Context, in *apipb.DeleteRuleRequest, _ ...grpc.CallOption) (*apipb.DeleteRuleResponse, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	// rule IDs are strings here; record that delete happened.
	f.deletedID = 1
	return apipb.DeleteRuleResponse_builder{}.Build(), nil
}

func (f *fakeWorkshopClient) CreateFileAccessRule(ctx context.Context, in *apipb.CreateFileAccessRuleRequest, _ ...grpc.CallOption) (*apipb.CreateFileAccessRuleResponse, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = true
	return apipb.CreateFileAccessRuleResponse_builder{RuleId: &f.newID}.Build(), nil
}

func (f *fakeWorkshopClient) DeleteFileAccessRule(ctx context.Context, in *apipb.DeleteFileAccessRuleRequest, _ ...grpc.CallOption) (*apipb.DeleteFileAccessRuleResponse, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deletedID = in.GetRuleId()
	return apipb.DeleteFileAccessRuleResponse_builder{}.Build(), nil
}

func (f *fakeWorkshopClient) CreatePackageRule(ctx context.Context, in *apipb.CreatePackageRuleRequest, _ ...grpc.CallOption) (*apipb.CreatePackageRuleResponse, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = true
	return apipb.CreatePackageRuleResponse_builder{RuleId: &f.newID}.Build(), nil
}

func (f *fakeWorkshopClient) DeletePackageRule(ctx context.Context, in *apipb.DeletePackageRuleRequest, _ ...grpc.CallOption) (*apipb.DeletePackageRuleResponse, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deletedID = in.GetRuleId()
	return apipb.DeletePackageRuleResponse_builder{}.Build(), nil
}

func TestResolveBlockReason(t *testing.T) {
	cases := []struct {
		policy string
		want   string // "" means null
	}{
		{"BLOCKLIST", "BLOCK_REASON_POLICY"},
		{"SILENT_BLOCKLIST", "BLOCK_REASON_POLICY"},
		{"SILENT_GUI_BLOCKLIST", "BLOCK_REASON_POLICY"},
		{"SILENT_TTY_BLOCKLIST", "BLOCK_REASON_POLICY"},
		{"ALLOWLIST", ""},
		{"ALLOWLIST_COMPILER", ""},
		{"SEATBELT", ""},
		{"CEL", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := resolveBlockReason(c.policy)
		if c.want == "" {
			if !got.IsNull() {
				t.Errorf("policy %q: expected null block_reason, got %q", c.policy, got.ValueString())
			}
			continue
		}
		if got.ValueString() != c.want {
			t.Errorf("policy %q: expected %q, got %q", c.policy, c.want, got.ValueString())
		}
	}
}

// --- workshop_rule -------------------------------------------------------

func TestUpsertRuleKeyUnchanged(t *testing.T) {
	fake := &fakeWorkshopClient{}
	r := &RuleResource{client: fake}

	state := RuleResourceModel{
		Identifier: types.StringValue("abc"),
		RuleType:   types.StringValue("BINARY"),
		Tag:        types.StringValue("global"),
		Policy:     types.StringValue("ALLOWLIST"),
		Id:         types.StringValue("rule-old"),
	}
	plan := state
	plan.Policy = types.StringValue("BLOCKLIST") // content change, key identical

	newID, diags := r.upsertRule(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if newID.ValueString() != "rule-new" {
		t.Errorf("expected new ID rule-new, got %q", newID.ValueString())
	}
	if !fake.created {
		t.Error("expected CreateRule (upsert) to be called")
	}
	if fake.deletedID != 0 {
		t.Error("key unchanged: old rule must NOT be deleted (server supersedes it)")
	}
}

func TestUpsertRuleKeyChangedDeletesOld(t *testing.T) {
	fake := &fakeWorkshopClient{}
	r := &RuleResource{client: fake}

	state := RuleResourceModel{
		Identifier: types.StringValue("abc"),
		RuleType:   types.StringValue("BINARY"),
		Tag:        types.StringValue("global"),
		Id:         types.StringValue("rule-old"),
	}
	plan := state
	plan.Identifier = types.StringValue("def") // key change

	newID, diags := r.upsertRule(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if newID.ValueString() != "rule-new" {
		t.Errorf("expected new ID rule-new, got %q", newID.ValueString())
	}
	if fake.deletedID == 0 {
		t.Error("key changed: old rule must be deleted")
	}
}

func TestUpsertRuleCreateErrorReturnsNullAndDoesNotDelete(t *testing.T) {
	fake := &fakeWorkshopClient{createErr: errors.New("boom")}
	r := &RuleResource{client: fake}

	state := RuleResourceModel{
		Identifier: types.StringValue("abc"),
		RuleType:   types.StringValue("BINARY"),
		Tag:        types.StringValue("global"),
		Id:         types.StringValue("rule-old"),
	}
	plan := state
	plan.Identifier = types.StringValue("def")

	newID, diags := r.upsertRule(context.Background(), plan, state)
	if !diags.HasError() {
		t.Error("expected an error diagnostic when the upsert fails")
	}
	if !newID.IsNull() {
		t.Errorf("expected null ID on failure, got %q", newID.ValueString())
	}
	if fake.deletedID != 0 {
		t.Error("upsert failed: the old rule must be left untouched")
	}
}

func TestUpsertRuleDeleteFailureIsWarningNotError(t *testing.T) {
	fake := &fakeWorkshopClient{deleteErr: errors.New("nope")}
	r := &RuleResource{client: fake}

	state := RuleResourceModel{
		Identifier: types.StringValue("abc"),
		RuleType:   types.StringValue("BINARY"),
		Tag:        types.StringValue("global"),
		Id:         types.StringValue("rule-old"),
	}
	plan := state
	plan.Identifier = types.StringValue("def") // key change triggers delete

	newID, diags := r.upsertRule(context.Background(), plan, state)
	if diags.HasError() {
		t.Errorf("a failed cleanup should be a warning, not an error: %v", diags)
	}
	if diags.WarningsCount() != 1 {
		t.Errorf("expected 1 warning, got %d", diags.WarningsCount())
	}
	if newID.ValueString() != "rule-new" {
		t.Errorf("new rule should still be tracked, got %q", newID.ValueString())
	}
}

// --- file_access_rule ----------------------------------------------------

func TestUpsertFileAccessRuleKeyChangeDeletesOld(t *testing.T) {
	fake := &fakeWorkshopClient{newID: 99}
	r := &FileAccessRuleResource{client: fake}

	state := FileAccessRuleResourceModel{
		Tag:      types.StringValue("global"),
		Name:     types.StringValue("old-name"),
		RuleType: types.StringValue("PathsWithAllowedProcesses"),
		Id:       types.Int64Value(42),
	}
	plan := state
	plan.Name = types.StringValue("new-name") // key change

	newID, diags := r.upsertFileAccessRule(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if newID.ValueInt64() != 99 {
		t.Errorf("expected new ID 99, got %d", newID.ValueInt64())
	}
	if fake.deletedID != 42 {
		t.Errorf("key changed: expected delete of old ID 42, got %d", fake.deletedID)
	}
}

func TestUpsertFileAccessRuleKeyUnchangedNoDelete(t *testing.T) {
	fake := &fakeWorkshopClient{newID: 99}
	r := &FileAccessRuleResource{client: fake}

	state := FileAccessRuleResourceModel{
		Tag:      types.StringValue("global"),
		Name:     types.StringValue("name"),
		RuleType: types.StringValue("PathsWithAllowedProcesses"),
		Id:       types.Int64Value(42),
	}
	plan := state
	plan.BlockViolations = types.BoolValue(true) // content-only change

	_, diags := r.upsertFileAccessRule(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if fake.deletedID != 0 {
		t.Errorf("key unchanged: old rule must not be deleted, deleted %d", fake.deletedID)
	}
}

// --- package_rule --------------------------------------------------------

func TestUpsertPackageRuleKeyChangeDeletesOld(t *testing.T) {
	fake := &fakeWorkshopClient{newID: 7}
	r := &PackageRuleResource{client: fake}

	state := PackageRuleResourceModel{
		Tag:      types.StringValue("global"),
		Source:   types.StringValue("PACKAGE_SOURCE_HOMEBREW"),
		Name:     types.StringValue("wget"),
		Policy:   types.StringValue("ALLOWLIST"),
		RuleType: types.StringValue("BINARY"),
		Id:       types.Int64Value(5),
	}
	plan := state
	plan.Source = types.StringValue("PACKAGE_SOURCE_NPM") // key change

	newID, diags := r.upsertPackageRule(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if newID.ValueInt64() != 7 {
		t.Errorf("expected new ID 7, got %d", newID.ValueInt64())
	}
	if fake.deletedID != 5 {
		t.Errorf("key changed: expected delete of old ID 5, got %d", fake.deletedID)
	}
}

func TestUpsertPackageRuleKeyUnchangedNoDelete(t *testing.T) {
	fake := &fakeWorkshopClient{newID: 7}
	r := &PackageRuleResource{client: fake}

	state := PackageRuleResourceModel{
		Tag:      types.StringValue("global"),
		Source:   types.StringValue("PACKAGE_SOURCE_HOMEBREW"),
		Name:     types.StringValue("wget"),
		Policy:   types.StringValue("ALLOWLIST"),
		RuleType: types.StringValue("BINARY"),
		Id:       types.Int64Value(5),
	}
	plan := state
	plan.Policy = types.StringValue("BLOCKLIST") // content-only change

	_, diags := r.upsertPackageRule(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if fake.deletedID != 0 {
		t.Errorf("key unchanged: old rule must not be deleted, deleted %d", fake.deletedID)
	}
}
