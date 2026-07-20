// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// fakeWorkshopClient embeds the full client interface (so it satisfies it) and
// only overrides the rule create/delete RPCs the update path uses. Any other
// call panics, which is what we want for a focused unit test. The Delete*
// methods record a call so tests can assert Update never deletes (the server
// supersedes the old rule; deletion only happens via the resource's Delete).
type fakeWorkshopClient struct {
	svcpb.WorkshopServiceClient

	createErr error
	newID     int64 // returned ruleId on create (int64-keyed resources)

	created       bool
	deleteCalls   int
	lastCreateReq *apipb.CreateRuleRequest // captured for payload assertions

	validateCELErr      error  // returned by ValidateCELRule
	validateCELExpr     string // captured expression
	validateCELCall     int    // number of ValidateCELRule calls
	validateCELSeatbelt bool   // CanReturnSeatbelt on the ValidateCELRule response

	syncDeleteCalls int // number of DeleteSyncSettings calls
	syncUpdateCalls int // number of UpdateSyncSettings calls
}

func (f *fakeWorkshopClient) DeleteSyncSettings(ctx context.Context, in *apipb.DeleteSyncSettingsRequest, _ ...grpc.CallOption) (*apipb.DeleteSyncSettingsResponse, error) {
	f.syncDeleteCalls++
	return apipb.DeleteSyncSettingsResponse_builder{}.Build(), nil
}

func (f *fakeWorkshopClient) UpdateSyncSettings(ctx context.Context, in *apipb.UpdateSyncSettingsRequest, _ ...grpc.CallOption) (*apipb.UpdateSyncSettingsResponse, error) {
	f.syncUpdateCalls++
	return apipb.UpdateSyncSettingsResponse_builder{}.Build(), nil
}

func (f *fakeWorkshopClient) ValidateCELRule(ctx context.Context, in *apipb.ValidateCELRuleRequest, _ ...grpc.CallOption) (*apipb.ValidateCELRuleResponse, error) {
	f.validateCELCall++
	f.validateCELExpr = in.GetExpression()
	if f.validateCELErr != nil {
		return nil, f.validateCELErr
	}
	return apipb.ValidateCELRuleResponse_builder{
		CanReturnSeatbelt: proto.Bool(f.validateCELSeatbelt),
	}.Build(), nil
}

func (f *fakeWorkshopClient) CreateRule(ctx context.Context, in *apipb.CreateRuleRequest, _ ...grpc.CallOption) (*apipb.CreateRuleResponse, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = true
	f.lastCreateReq = in
	return apipb.CreateRuleResponse_builder{RuleId: proto.String("rule-new")}.Build(), nil
}

func (f *fakeWorkshopClient) DeleteRule(ctx context.Context, in *apipb.DeleteRuleRequest, _ ...grpc.CallOption) (*apipb.DeleteRuleResponse, error) {
	f.deleteCalls++
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
	f.deleteCalls++
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
	f.deleteCalls++
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

func TestUpsertRuleUpsertsAndNeverDeletes(t *testing.T) {
	fake := &fakeWorkshopClient{}
	r := &RuleResource{client: fake}

	plan := RuleResourceModel{
		Identifier: types.StringValue("abc"),
		RuleType:   types.StringValue("BINARY"),
		Tag:        types.StringValue("global"),
		Policy:     types.StringValue("BLOCKLIST"),
	}

	newID, diags := r.upsertRule(context.Background(), plan)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if newID.ValueString() != "rule-new" {
		t.Errorf("expected new ID rule-new, got %q", newID.ValueString())
	}
	if !fake.created {
		t.Error("expected CreateRule (upsert) to be called")
	}
	// The server supersedes the old rule; the provider must never delete it
	// during an update (key changes are RequiresReplace, handled by Delete).
	if fake.deleteCalls != 0 {
		t.Errorf("Update must not delete; got %d delete calls", fake.deleteCalls)
	}
}

// TestUpsertRulePropagatesBlockReason verifies the block_reason on the plan
// (already resolved by blockReasonDefault) is sent on the upsert request. It
// covers both the defaulted POLICY value and an explicit MALICIOUS value, and
// confirms an unset reason is not sent.
func TestUpsertRulePropagatesBlockReason(t *testing.T) {
	cases := []struct {
		name        string
		blockReason types.String
		want        apipb.Rule_BlockReason
	}{
		{"defaulted policy", types.StringValue("BLOCK_REASON_POLICY"), apipb.Rule_BLOCK_REASON_POLICY},
		{"explicit malicious", types.StringValue("BLOCK_REASON_MALICIOUS"), apipb.Rule_BLOCK_REASON_MALICIOUS},
		{"unset", types.StringNull(), apipb.Rule_BLOCK_REASON_UNSPECIFIED},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeWorkshopClient{}
			r := &RuleResource{client: fake}

			plan := RuleResourceModel{
				Identifier:  types.StringValue("abc"),
				RuleType:    types.StringValue("BINARY"),
				Tag:         types.StringValue("global"),
				Policy:      types.StringValue("BLOCKLIST"),
				BlockReason: c.blockReason,
			}

			if _, diags := r.upsertRule(context.Background(), plan); diags.HasError() {
				t.Fatalf("unexpected error diags: %v", diags)
			}
			got := fake.lastCreateReq.GetRule().GetBlockReason()
			if got != c.want {
				t.Errorf("block_reason: got %v, want %v", got, c.want)
			}
		})
	}
}

// TestBuildCreateRuleRequestSeatbeltPolicy verifies a SEATBELT rule sends its
// seatbelt_policy on the upsert request, and that it is not sent when unset.
func TestBuildCreateRuleRequestSeatbeltPolicy(t *testing.T) {
	req := buildCreateRuleRequest(RuleResourceModel{
		Identifier:     types.StringValue("abc"),
		RuleType:       types.StringValue("BINARY"),
		Tag:            types.StringValue("global"),
		Policy:         types.StringValue("SEATBELT"),
		SeatbeltPolicy: types.StringValue("my-profile"),
	})
	if got := req.GetRule().GetSeatbeltPolicy(); got != "my-profile" {
		t.Errorf("seatbelt_policy: got %q, want %q", got, "my-profile")
	}

	req = buildCreateRuleRequest(RuleResourceModel{
		Identifier: types.StringValue("abc"),
		RuleType:   types.StringValue("BINARY"),
		Tag:        types.StringValue("global"),
		Policy:     types.StringValue("BLOCKLIST"),
	})
	if got := req.GetRule().GetSeatbeltPolicy(); got != "" {
		t.Errorf("seatbelt_policy should be unset, got %q", got)
	}
}

func TestUpsertRuleCreateErrorReturnsNull(t *testing.T) {
	fake := &fakeWorkshopClient{createErr: errors.New("boom")}
	r := &RuleResource{client: fake}

	plan := RuleResourceModel{
		Identifier: types.StringValue("abc"),
		RuleType:   types.StringValue("BINARY"),
		Tag:        types.StringValue("global"),
		Policy:     types.StringValue("BLOCKLIST"),
	}

	newID, diags := r.upsertRule(context.Background(), plan)
	if !diags.HasError() {
		t.Error("expected an error diagnostic when the upsert fails")
	}
	if !newID.IsNull() {
		t.Errorf("expected null ID on failure, got %q", newID.ValueString())
	}
	if fake.deleteCalls != 0 {
		t.Errorf("upsert failed: nothing should be deleted; got %d delete calls", fake.deleteCalls)
	}
}

func TestValidateCELExpr(t *testing.T) {
	cases := []struct {
		name           string
		policy         types.String
		celExpr        types.String
		seatbeltPolicy types.String
		validErr       error
		canSeatbelt    bool
		wantCall       bool
		wantError      bool
	}{
		{"valid CEL", types.StringValue("CEL"), types.StringValue("true"), types.StringNull(), nil, false, true, false},
		{"invalid CEL", types.StringValue("CEL"), types.StringValue("bad("), types.StringNull(), status.Error(codes.InvalidArgument, "syntax error"), false, true, true},
		{"non-CEL policy skips", types.StringValue("BLOCKLIST"), types.StringValue("true"), types.StringNull(), nil, false, false, false},
		{"empty expr skips", types.StringValue("CEL"), types.StringValue(""), types.StringNull(), nil, false, false, false},
		{"unknown expr skips", types.StringValue("CEL"), types.StringUnknown(), types.StringNull(), nil, false, false, false},
		{"seatbelt required when unset", types.StringValue("CEL"), types.StringValue("true"), types.StringNull(), nil, true, true, true},
		{"seatbelt satisfied when set", types.StringValue("CEL"), types.StringValue("true"), types.StringValue("profile"), nil, true, true, false},
		{"seatbelt unknown skips", types.StringValue("CEL"), types.StringValue("true"), types.StringUnknown(), nil, true, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeWorkshopClient{validateCELErr: c.validErr, validateCELSeatbelt: c.canSeatbelt}
			r := &RuleResource{client: fake}

			diags := r.validateCELExpr(context.Background(), c.policy, c.celExpr, c.seatbeltPolicy)
			if diags.HasError() != c.wantError {
				t.Errorf("HasError() = %v, want %v (%v)", diags.HasError(), c.wantError, diags)
			}
			// On a gRPC error, only the status desc ("syntax error") should
			// surface, not the full gRPC error string ("rpc error: code = ...").
			if c.validErr != nil && diags.HasError() {
				if detail := diags.Errors()[0].Detail(); !strings.HasSuffix(detail, "syntax error") {
					t.Errorf("detail = %q, want it to end with the bare desc", detail)
				}
			}
			if (fake.validateCELCall > 0) != c.wantCall {
				t.Errorf("ValidateCELRule called %d times, wantCall=%v", fake.validateCELCall, c.wantCall)
			}
		})
	}
}

// --- file_access_rule ----------------------------------------------------

func TestUpsertFileAccessRuleUpsertsAndNeverDeletes(t *testing.T) {
	fake := &fakeWorkshopClient{newID: 99}
	r := &FileAccessRuleResource{client: fake}

	plan := FileAccessRuleResourceModel{
		Tag:      types.StringValue("global"),
		Name:     types.StringValue("name"),
		RuleType: types.StringValue("PathsWithAllowedProcesses"),
	}

	newID, diags := r.upsertFileAccessRule(context.Background(), plan)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if newID.ValueInt64() != 99 {
		t.Errorf("expected new ID 99, got %d", newID.ValueInt64())
	}
	if fake.deleteCalls != 0 {
		t.Errorf("Update must not delete; got %d delete calls", fake.deleteCalls)
	}
}

// --- package_rule --------------------------------------------------------

func TestUpsertPackageRuleUpsertsAndNeverDeletes(t *testing.T) {
	fake := &fakeWorkshopClient{newID: 7}
	r := &PackageRuleResource{client: fake}

	plan := PackageRuleResourceModel{
		Tag:      types.StringValue("global"),
		Source:   types.StringValue("PACKAGE_SOURCE_HOMEBREW"),
		Name:     types.StringValue("wget"),
		Policy:   types.StringValue("ALLOWLIST"),
		RuleType: types.StringValue("BINARY"),
	}

	newID, diags := r.upsertPackageRule(context.Background(), plan)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if newID.ValueInt64() != 7 {
		t.Errorf("expected new ID 7, got %d", newID.ValueInt64())
	}
	if fake.deleteCalls != 0 {
		t.Errorf("Update must not delete; got %d delete calls", fake.deleteCalls)
	}
}
