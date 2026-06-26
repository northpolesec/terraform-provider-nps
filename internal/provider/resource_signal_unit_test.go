// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"errors"
	"testing"

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
// focused unit test.
type fakeSignalClient struct {
	svcpb.WorkshopServiceClient

	upsertErr error
	deleteErr error

	upserted    bool
	deletedName string // "" means no delete happened
	deletedTag  string
}

func (f *fakeSignalClient) UpsertSignal(ctx context.Context, in *apipb.UpsertSignalRequest, _ ...grpc.CallOption) (*apipb.UpsertSignalResponse, error) {
	if f.upsertErr != nil {
		return nil, f.upsertErr
	}
	f.upserted = true
	return apipb.UpsertSignalResponse_builder{Signal: in.GetSignal()}.Build(), nil
}

func (f *fakeSignalClient) DeleteSignal(ctx context.Context, in *apipb.DeleteSignalRequest, _ ...grpc.CallOption) (*apipb.DeleteSignalResponse, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deletedName = in.GetName()
	f.deletedTag = in.GetTag()
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

func TestUpsertSignalKeyUnchangedNoDelete(t *testing.T) {
	fake := &fakeSignalClient{}
	r := &SignalResource{client: fake}

	state := testSignalModel()
	plan := state
	plan.Severity = types.StringValue("SEVERITY_CRITICAL") // content-only change

	diags := r.upsertSignal(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if !fake.upserted {
		t.Error("expected UpsertSignal to be called")
	}
	if fake.deletedName != "" {
		t.Errorf("key unchanged: old signal must NOT be deleted, deleted %q", fake.deletedName)
	}
}

func TestUpsertSignalKeyChangedDeletesOld(t *testing.T) {
	fake := &fakeSignalClient{}
	r := &SignalResource{client: fake}

	state := testSignalModel()
	plan := state
	plan.Name = types.StringValue("CRED-002") // key change

	diags := r.upsertSignal(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if fake.deletedName != "CRED-001" || fake.deletedTag != "global" {
		t.Errorf("key changed: expected delete of old (CRED-001, global), got (%q, %q)", fake.deletedName, fake.deletedTag)
	}
}

func TestUpsertSignalTagChangedDeletesOld(t *testing.T) {
	fake := &fakeSignalClient{}
	r := &SignalResource{client: fake}

	state := testSignalModel()
	plan := state
	plan.Tag = types.StringValue("engineering") // key change via tag

	diags := r.upsertSignal(context.Background(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected error diags: %v", diags)
	}
	if fake.deletedName != "CRED-001" || fake.deletedTag != "global" {
		t.Errorf("tag changed: expected delete of old (CRED-001, global), got (%q, %q)", fake.deletedName, fake.deletedTag)
	}
}

func TestUpsertSignalUpsertErrorDoesNotDelete(t *testing.T) {
	fake := &fakeSignalClient{upsertErr: errors.New("boom")}
	r := &SignalResource{client: fake}

	state := testSignalModel()
	plan := state
	plan.Name = types.StringValue("CRED-002") // key change

	diags := r.upsertSignal(context.Background(), plan, state)
	if !diags.HasError() {
		t.Error("expected an error diagnostic when the upsert fails")
	}
	if fake.deletedName != "" {
		t.Error("upsert failed: the old signal must be left untouched")
	}
}

func TestUpsertSignalDeleteFailureIsWarningNotError(t *testing.T) {
	fake := &fakeSignalClient{deleteErr: errors.New("nope")}
	r := &SignalResource{client: fake}

	state := testSignalModel()
	plan := state
	plan.Name = types.StringValue("CRED-002") // key change triggers delete

	diags := r.upsertSignal(context.Background(), plan, state)
	if diags.HasError() {
		t.Errorf("a failed cleanup should be a warning, not an error: %v", diags)
	}
	if diags.WarningsCount() != 1 {
		t.Errorf("expected 1 warning, got %d", diags.WarningsCount())
	}
}
