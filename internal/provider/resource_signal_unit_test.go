// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/common"
	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestSignalReadFilter(t *testing.T) {
	got := signalReadFilter("CRED-001", "global")
	want := `name = "CRED-001" AND tag = "global"`
	if got != want {
		t.Errorf("signalReadFilter() = %q, want %q", got, want)
	}
}

func TestParseSignalImportID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantTag string
		wantSig string
		wantErr bool
	}{
		{name: "valid", id: "global/CRED-001", wantTag: "global", wantSig: "CRED-001"},
		{name: "name contains slash", id: "global/CRED/001", wantTag: "global", wantSig: "CRED/001"},
		{name: "no separator", id: "CRED-001", wantErr: true},
		{name: "empty tag", id: "/CRED-001", wantErr: true},
		{name: "empty name", id: "global/", wantErr: true},
		{name: "empty", id: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, sig, err := parseSignalImportID(tt.id)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSignalImportID(%q) = (%q, %q, nil), want error", tt.id, tag, sig)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSignalImportID(%q) unexpected error: %v", tt.id, err)
			}
			if tag != tt.wantTag || sig != tt.wantSig {
				t.Errorf("parseSignalImportID(%q) = (%q, %q), want (%q, %q)", tt.id, tag, sig, tt.wantTag, tt.wantSig)
			}
		})
	}
}

// TestSignalSeverityRoundTrip guards the assumption that the severity strings
// accepted by the schema validator map back to the same enum name the API
// returns via Severity.String() — the contract Read and List rely on.
func TestSignalSeverityRoundTrip(t *testing.T) {
	for name, val := range commonpb.Severity_value {
		if got := commonpb.Severity(val).String(); got != name {
			t.Errorf("Severity %q round-trips to %q", name, got)
		}
	}
}

// fakeSignalClient embeds the full client interface (so it satisfies it) and
// only overrides the signal upsert/delete RPCs the update path uses. Any other
// call would panic on the nil embedded client, which is what we want for a
// focused unit test. DeleteSignal records a call so tests can assert Update
// never deletes (the server supersedes the old signal; deletion only happens
// via the resource's Delete, since the natural key is RequiresReplace).
type fakeSignalClient struct {
	svcpb.WorkshopServiceClient

	upsertErr error
	deleteErr error

	upserted      bool
	deleteCalls   int
	lastUpsertReq *apipb.UpsertSignalRequest // captured for payload assertions
}

func (f *fakeSignalClient) UpsertSignal(ctx context.Context, in *apipb.UpsertSignalRequest, _ ...grpc.CallOption) (*apipb.UpsertSignalResponse, error) {
	if f.upsertErr != nil {
		return nil, f.upsertErr
	}
	f.upserted = true
	f.lastUpsertReq = in
	return apipb.UpsertSignalResponse_builder{Signal: in.GetSignal()}.Build(), nil
}

func (f *fakeSignalClient) DeleteSignal(ctx context.Context, in *apipb.DeleteSignalRequest, _ ...grpc.CallOption) (*apipb.DeleteSignalResponse, error) {
	f.deleteCalls++
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return apipb.DeleteSignalResponse_builder{}.Build(), nil
}

func testSignalModel() SignalResourceModel {
	return SignalResourceModel{
		Name:       types.StringValue("CRED-001"),
		Tag:        types.StringValue("global"),
		Severity:   types.StringValue("SEVERITY_HIGH"),
		Expression: types.StringValue("true"),
		Disabled:   types.BoolValue(false),
		Labels:     types.SetNull(types.StringType),
	}
}

// callSignalUpdate drives SignalResource.Update with a plan built from model,
// wiring the Plan/State/Identity the framework would normally pre-populate so
// the real Update flow (not just the shared upsert helper) is exercised.
func callSignalUpdate(t *testing.T, r *SignalResource, model SignalResourceModel) *resource.UpdateResponse {
	t.Helper()
	ctx := context.Background()

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	var iResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)

	req := resource.UpdateRequest{Plan: tfsdk.Plan{Schema: sResp.Schema}}
	if diags := req.Plan.Set(ctx, model); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags)
	}
	resp := &resource.UpdateResponse{
		State:    tfsdk.State{Schema: sResp.Schema},
		Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
	}
	r.Update(ctx, req, resp)
	return resp
}

func callSignalDelete(t *testing.T, r *SignalResource, model SignalResourceModel) *resource.DeleteResponse {
	t.Helper()
	ctx := context.Background()

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	req := resource.DeleteRequest{State: tfsdk.State{Schema: sResp.Schema}}
	if diags := req.State.Set(ctx, model); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(ctx, req, resp)
	return resp
}

func TestSignalDeleteTreatsNotFoundAsSuccess(t *testing.T) {
	fake := &fakeSignalClient{deleteErr: status.Error(codes.NotFound, "gone")}
	r := &SignalResource{client: fake}

	resp := callSignalDelete(t, r, testSignalModel())
	if resp.Diagnostics.HasError() {
		t.Fatalf("NotFound should be an idempotent delete: %v", resp.Diagnostics)
	}
	if fake.deleteCalls != 1 {
		t.Fatalf("DeleteSignal calls = %d, want 1", fake.deleteCalls)
	}
}

func TestSignalDeleteDoesNotIgnoreSupersededRuleError(t *testing.T) {
	fake := &fakeSignalClient{deleteErr: status.Error(codes.InvalidArgument, "rule is superseded")}
	r := &SignalResource{client: fake}

	resp := callSignalDelete(t, r, testSignalModel())
	if !resp.Diagnostics.HasError() {
		t.Fatal("signal delete must not ignore a rule-ID-specific superseded error")
	}
	if fake.deleteCalls != 1 {
		t.Fatalf("DeleteSignal calls = %d, want 1", fake.deleteCalls)
	}
}

// TestSignalUpdateUpsertsAndNeverDeletes verifies an in-place update upserts and
// never deletes: the natural key is RequiresReplace, so the server is
// guaranteed to supersede the existing signal sharing the key.
func TestSignalUpdateUpsertsAndNeverDeletes(t *testing.T) {
	fake := &fakeSignalClient{}
	r := &SignalResource{client: fake}

	plan := testSignalModel()
	plan.Severity = types.StringValue("CRITICAL") // non-key change

	resp := callSignalUpdate(t, r, plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	if !fake.upserted {
		t.Error("expected UpsertSignal to be called")
	}
	if fake.deleteCalls != 0 {
		t.Errorf("Update must not delete; got %d delete calls", fake.deleteCalls)
	}
}

func TestSignalUpdateErrorSurfacesDiagnostic(t *testing.T) {
	fake := &fakeSignalClient{upsertErr: errors.New("boom")}
	r := &SignalResource{client: fake}

	resp := callSignalUpdate(t, r, testSignalModel())
	if !resp.Diagnostics.HasError() {
		t.Error("expected an error diagnostic when the upsert fails")
	}
	if fake.deleteCalls != 0 {
		t.Errorf("upsert failed: nothing should be deleted; got %d delete calls", fake.deleteCalls)
	}
}

// TestUpsertSignalPropagatesFields verifies the model fields are mapped onto the
// upsert payload, including the severity enum string -> enum value conversion.
func TestUpsertSignalPropagatesFields(t *testing.T) {
	fake := &fakeSignalClient{}
	r := &SignalResource{client: fake}

	plan := SignalResourceModel{
		Name:        types.StringValue("CRED-007"),
		Tag:         types.StringValue("engineering"),
		Description: types.StringValue("cookie theft"),
		Severity:    types.StringValue("CRITICAL"),
		Expression:  types.StringValue("event.file.path == '/x'"),
		Disabled:    types.BoolValue(true),
		Labels:      types.SetValueMust(types.StringType, []attr.Value{types.StringValue("cred"), types.StringValue("theft")}),
	}

	if _, err := r.upsert(context.Background(), plan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := fake.lastUpsertReq.GetSignal()
	if got.GetName() != "CRED-007" || got.GetTag() != "engineering" {
		t.Errorf("key: got (%q, %q)", got.GetName(), got.GetTag())
	}
	if got.GetSeverity() != commonpb.Severity_SEVERITY_CRITICAL {
		t.Errorf("severity: got %v, want SEVERITY_CRITICAL", got.GetSeverity())
	}
	if got.GetDescription() != "cookie theft" || got.GetExpression() != "event.file.path == '/x'" {
		t.Errorf("description/expression not propagated: %q / %q", got.GetDescription(), got.GetExpression())
	}
	if !got.GetDisabled() {
		t.Error("disabled not propagated")
	}
	if gotLabels := got.GetLabels(); len(gotLabels) != 2 {
		t.Errorf("labels not propagated: got %v", gotLabels)
	}
}

// TestOSTypeToModel checks the round trip of the signal's os_type. An unset
// os_type is stored as macOS, so an UNSPECIFIED value from the server must
// read back as MACOS: mapping it to null would diff against the schema's MACOS
// default on every plan. A refresh keeps whichever spelling is in state.
func TestOSTypeToModel(t *testing.T) {
	for _, c := range []struct {
		name  string
		prior types.String
		os    apipb.OSType
		want  types.String
	}{
		{"unspecified reads back as macOS", types.StringNull(), apipb.OSType_OS_TYPE_UNSPECIFIED, types.StringValue("MACOS")},
		{"unspecified keeps a prior macOS spelling", types.StringValue("OS_TYPE_MACOS"), apipb.OSType_OS_TYPE_UNSPECIFIED, types.StringValue("OS_TYPE_MACOS")},
		{"null prior takes the short form", types.StringNull(), apipb.OSType_OS_TYPE_LINUX, types.StringValue("LINUX")},
		{"keeps the short spelling", types.StringValue("MACOS"), apipb.OSType_OS_TYPE_MACOS, types.StringValue("MACOS")},
		{"keeps the prefixed spelling", types.StringValue("OS_TYPE_MACOS"), apipb.OSType_OS_TYPE_MACOS, types.StringValue("OS_TYPE_MACOS")},
		{"rewrites a real change", types.StringValue("OS_TYPE_MACOS"), apipb.OSType_OS_TYPE_WINDOWS, types.StringValue("WINDOWS")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := osTypeToModel(c.prior, c.os); !got.Equal(c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestSignalComputedAttributesPreserveServerValues checks os_type and
// full_process_tree carry no static default. A default would plan MACOS/false
// for an existing signal whose configuration says nothing about them, quietly
// retargeting a LINUX signal or turning off full-tree reporting on the first
// apply after upgrading the provider. UseStateForUnknown keeps the refreshed
// value instead; a new signal still lands on the server's defaults.
func TestSignalComputedAttributesPreserveServerValues(t *testing.T) {
	ctx := context.Background()
	var sResp resource.SchemaResponse
	(&SignalResource{}).Schema(ctx, resource.SchemaRequest{}, &sResp)

	osType, ok := sResp.Schema.Attributes["os_type"].(schema.StringAttribute)
	if !ok {
		t.Fatal("os_type is not a StringAttribute")
	}
	if osType.Default != nil {
		t.Error("os_type must not carry a static default; it would retarget an existing signal")
	}
	if !osType.Computed {
		t.Error("os_type must be Computed so an omitted value can track the server")
	}

	tree, ok := sResp.Schema.Attributes["full_process_tree"].(schema.BoolAttribute)
	if !ok {
		t.Fatal("full_process_tree is not a BoolAttribute")
	}
	if tree.Default != nil {
		t.Error("full_process_tree must not carry a static default")
	}
	if !tree.Computed {
		t.Error("full_process_tree must be Computed")
	}
}

// TestResolveSignalComputed checks an apply never leaves an unknown in state,
// and that a value the configuration did set is untouched.
func TestResolveSignalComputed(t *testing.T) {
	stored := apipb.Signal_builder{
		OsType:          apipb.OSType_OS_TYPE_LINUX,
		FullProcessTree: true,
	}.Build()

	// Unset in configuration: both resolve from what the server stored.
	data := SignalResourceModel{OsType: types.StringUnknown(), FullProcessTree: types.BoolUnknown()}
	resolveSignalComputed(&data, stored)
	if data.OsType.ValueString() != "LINUX" {
		t.Errorf("os_type: got %v, want LINUX", data.OsType)
	}
	if !data.FullProcessTree.ValueBool() {
		t.Errorf("full_process_tree: got %v, want true", data.FullProcessTree)
	}

	// An unset os_type is stored as macOS, so a new signal lands there.
	fresh := SignalModelUnknown()
	resolveSignalComputed(&fresh, apipb.Signal_builder{}.Build())
	if fresh.OsType.ValueString() != "MACOS" {
		t.Errorf("os_type: got %v, want MACOS", fresh.OsType)
	}
	if fresh.FullProcessTree.ValueBool() {
		t.Errorf("full_process_tree: got %v, want false", fresh.FullProcessTree)
	}

	// A configured value is left alone.
	configured := SignalResourceModel{OsType: types.StringValue("OS_TYPE_WINDOWS"), FullProcessTree: types.BoolValue(false)}
	resolveSignalComputed(&configured, stored)
	if configured.OsType.ValueString() != "OS_TYPE_WINDOWS" {
		t.Errorf("os_type: got %v, want the configured OS_TYPE_WINDOWS", configured.OsType)
	}
	if configured.FullProcessTree.ValueBool() {
		t.Errorf("full_process_tree: got %v, want the configured false", configured.FullProcessTree)
	}
}

// SignalModelUnknown is a model with both computed attributes unresolved, as
// the framework hands them to Create when the configuration omits them.
func SignalModelUnknown() SignalResourceModel {
	return SignalResourceModel{OsType: types.StringUnknown(), FullProcessTree: types.BoolUnknown()}
}

// TestUpsertSignalPropagatesOSTypeAndProcessTree checks the two fields the
// upsert used to drop, silently resetting them to their zero values on every
// apply.
func TestUpsertSignalPropagatesOSTypeAndProcessTree(t *testing.T) {
	for _, c := range []struct {
		name   string
		osType types.String
		want   apipb.OSType
	}{
		{"short spelling", types.StringValue("LINUX"), apipb.OSType_OS_TYPE_LINUX},
		{"prefixed spelling", types.StringValue("OS_TYPE_WINDOWS"), apipb.OSType_OS_TYPE_WINDOWS},
		// A null model value only reaches the upsert from a caller that bypasses
		// the schema default; the server stores UNSPECIFIED as macOS anyway.
		{"null sends unspecified", types.StringNull(), apipb.OSType_OS_TYPE_UNSPECIFIED},
	} {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeSignalClient{}
			r := &SignalResource{client: fake}

			plan := testSignalModel()
			plan.OsType = c.osType
			plan.FullProcessTree = types.BoolValue(true)

			if _, err := r.upsert(context.Background(), plan); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := fake.lastUpsertReq.GetSignal()
			if got.GetOsType() != c.want {
				t.Errorf("os_type: got %v, want %v", got.GetOsType(), c.want)
			}
			if !got.GetFullProcessTree() {
				t.Error("full_process_tree not propagated")
			}
		})
	}
}
