// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"google.golang.org/grpc"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

type fakeAPIKeyClient struct {
	svcpb.WorkshopServiceClient

	updateErr error

	updateCalls   int
	lastUpdateReq *apipb.UpdateAPIKeyRequest
}

func (f *fakeAPIKeyClient) UpdateAPIKey(ctx context.Context, in *apipb.UpdateAPIKeyRequest, _ ...grpc.CallOption) (*apipb.UpdateAPIKeyResponse, error) {
	f.updateCalls++
	f.lastUpdateReq = in
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return apipb.UpdateAPIKeyResponse_builder{}.Build(), nil
}

func testAPIKeyModel() APIKeyResourceModel {
	return APIKeyResourceModel{
		Name:        types.StringValue("ci"),
		Permissions: types.ListValueMust(types.StringType, []attr.Value{types.StringValue("read:rules")}),
		Lifetime:    types.Int64Value(48),
		Secret:      types.StringValue("s3cret"),
		Expires:     types.StringValue("2027-01-01T00:00:00Z"),
	}
}

// callAPIKeyUpdate drives APIKeyResource.Update with the Plan/State/Identity the
// framework would normally pre-populate, so the real Update flow runs.
func callAPIKeyUpdate(t *testing.T, r *APIKeyResource, plan, state APIKeyResourceModel) *resource.UpdateResponse {
	t.Helper()
	ctx := context.Background()

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	var iResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: sResp.Schema},
		State: tfsdk.State{Schema: sResp.Schema},
	}
	if diags := req.Plan.Set(ctx, plan); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags)
	}
	if diags := req.State.Set(ctx, state); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	resp := &resource.UpdateResponse{
		State:    tfsdk.State{Schema: sResp.Schema},
		Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
	}
	r.Update(ctx, req, resp)
	return resp
}

// TestAPIKeyUpdateCallsUpdateAPIKey is the regression test for an Update that
// used to write state and return without calling the API at all, so a
// permissions change reported success and changed nothing server-side.
func TestAPIKeyUpdateCallsUpdateAPIKey(t *testing.T) {
	fake := &fakeAPIKeyClient{}
	r := &APIKeyResource{client: fake}

	state := testAPIKeyModel()
	plan := testAPIKeyModel()
	plan.Permissions = types.ListValueMust(types.StringType, []attr.Value{
		types.StringValue("read:rules"), types.StringValue("write:rules"),
	})

	resp := callAPIKeyUpdate(t, r, plan, state)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	if fake.updateCalls != 1 {
		t.Fatalf("UpdateAPIKey calls = %d, want 1", fake.updateCalls)
	}
	got := fake.lastUpdateReq
	if got.GetName() != "ci" {
		t.Errorf("name: got %q", got.GetName())
	}
	if len(got.GetPermissions()) != 2 {
		t.Errorf("permissions not propagated: %v", got.GetPermissions())
	}
}

// TestAPIKeyUpdatePreservesExpiryWhenLifetimeUnchanged checks a permission-only
// change carries the current expiry forward. UpdateAPIKey replaces the expiry
// on every call, so deriving it from the lifetime unconditionally would
// silently extend the key on every unrelated edit.
func TestAPIKeyUpdatePreservesExpiryWhenLifetimeUnchanged(t *testing.T) {
	fake := &fakeAPIKeyClient{}
	r := &APIKeyResource{client: fake}

	state := testAPIKeyModel()
	plan := testAPIKeyModel()
	plan.Permissions = types.ListValueMust(types.StringType, []attr.Value{types.StringValue("write:rules")})

	resp := callAPIKeyUpdate(t, r, plan, state)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}

	want, err := time.Parse(time.RFC3339, "2027-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if got := fake.lastUpdateReq.GetExpires().AsTime(); !got.Equal(want) {
		t.Errorf("expires: got %v, want the prior state's %v", got, want)
	}

	var final APIKeyResourceModel
	if diags := resp.State.Get(context.Background(), &final); diags.HasError() {
		t.Fatalf("reading final state: %v", diags)
	}
	if final.Expires.ValueString() != "2027-01-01T00:00:00Z" {
		t.Errorf("state expires: got %q", final.Expires.ValueString())
	}
}

// TestAPIKeyUpdateRebasesExpiryWhenLifetimeChanges checks a lifetime change
// does move the expiry, relative to the time of the apply.
func TestAPIKeyUpdateRebasesExpiryWhenLifetimeChanges(t *testing.T) {
	fake := &fakeAPIKeyClient{}
	r := &APIKeyResource{client: fake}

	state := testAPIKeyModel()
	plan := testAPIKeyModel()
	plan.Lifetime = types.Int64Value(1)

	before := time.Now()
	resp := callAPIKeyUpdate(t, r, plan, state)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}

	got := fake.lastUpdateReq.GetExpires().AsTime()
	if got.Before(before.Add(59*time.Minute)) || got.After(time.Now().Add(61*time.Minute)) {
		t.Errorf("expires: got %v, want roughly one hour from now", got)
	}
}

func TestAPIKeyUpdateErrorSurfacesDiagnostic(t *testing.T) {
	fake := &fakeAPIKeyClient{updateErr: context.DeadlineExceeded}
	r := &APIKeyResource{client: fake}

	plan := testAPIKeyModel()
	plan.Lifetime = types.Int64Value(1)

	resp := callAPIKeyUpdate(t, r, plan, testAPIKeyModel())
	if !resp.Diagnostics.HasError() {
		t.Error("expected an error diagnostic when UpdateAPIKey fails")
	}
}

func TestAPIKeyLifetime(t *testing.T) {
	for _, c := range []struct {
		in   types.Int64
		want time.Duration
	}{
		{types.Int64Null(), defaultAPIKeyLifetimeHours * time.Hour},
		{types.Int64Value(0), defaultAPIKeyLifetimeHours * time.Hour},
		{types.Int64Value(48), 48 * time.Hour},
	} {
		if got := apiKeyLifetime(c.in); got != c.want {
			t.Errorf("apiKeyLifetime(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestAPIKeyImportStateUsesName is the regression test for an import that
// passed the ID through to a path.Root("id") the schema does not have. An API
// key is identified by its name.
func TestAPIKeyImportStateUsesName(t *testing.T) {
	ctx := context.Background()
	r := &APIKeyResource{}

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	if _, ok := sResp.Schema.Attributes["id"]; ok {
		t.Fatal("schema now has an id attribute; revisit ImportState")
	}

	resp := &resource.ImportStateResponse{State: emptyState(ctx, sResp.Schema)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "ci"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}

	var name types.String
	if diags := resp.State.GetAttribute(ctx, path.Root("name"), &name); diags.HasError() {
		t.Fatalf("reading name: %v", diags)
	}
	if name.ValueString() != "ci" {
		t.Errorf("name: got %q, want %q", name.ValueString(), "ci")
	}
}

func TestAPIKeyImportStateRejectsEmptyID(t *testing.T) {
	ctx := context.Background()
	r := &APIKeyResource{}

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)

	resp := &resource.ImportStateResponse{State: emptyState(ctx, sResp.Schema)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: ""}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected an error diagnostic for an empty import ID")
	}
}

// emptyState builds the null-object state the framework hands ImportState, so
// SetAttribute has a typed value to write into.
func emptyState(ctx context.Context, s schema.Schema) tfsdk.State {
	return tfsdk.State{
		Schema: s,
		Raw:    tftypes.NewValue(s.Type().TerraformType(ctx), nil),
	}
}
