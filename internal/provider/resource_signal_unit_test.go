// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"

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
	return apipb.DeleteSignalResponse_builder{}.Build(), nil
}

func testSignalModel() SignalResourceModel {
	return SignalResourceModel{
		Name:       types.StringValue("CRED-001"),
		Tag:        types.StringValue("global"),
		Severity:   types.StringValue("SEVERITY_HIGH"),
		Expression: types.StringValue("true"),
		Disabled:   types.BoolValue(false),
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

// TestSignalUpdateUpsertsAndNeverDeletes verifies an in-place update upserts and
// never deletes: the natural key is RequiresReplace, so the server is
// guaranteed to supersede the existing signal sharing the key.
func TestSignalUpdateUpsertsAndNeverDeletes(t *testing.T) {
	fake := &fakeSignalClient{}
	r := &SignalResource{client: fake}

	plan := testSignalModel()
	plan.Severity = types.StringValue("SEVERITY_CRITICAL") // non-key change

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
		Severity:    types.StringValue("SEVERITY_CRITICAL"),
		Expression:  types.StringValue("event.file.path == '/x'"),
		Disabled:    types.BoolValue(true),
	}

	if err := r.upsert(context.Background(), plan); err != nil {
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
}
