// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

type fakeTagClient struct {
	svcpb.WorkshopServiceClient

	renameErr error

	renameCalls   int
	deleteCalls   int
	createCalls   int
	lastRenameReq *apipb.RenameTagRequest
}

func (f *fakeTagClient) RenameTag(ctx context.Context, in *apipb.RenameTagRequest, _ ...grpc.CallOption) (*apipb.RenameTagResponse, error) {
	f.renameCalls++
	f.lastRenameReq = in
	if f.renameErr != nil {
		return nil, f.renameErr
	}
	return apipb.RenameTagResponse_builder{}.Build(), nil
}

func (f *fakeTagClient) DeleteTag(ctx context.Context, in *apipb.DeleteTagRequest, _ ...grpc.CallOption) (*apipb.DeleteTagResponse, error) {
	f.deleteCalls++
	return apipb.DeleteTagResponse_builder{}.Build(), nil
}

func (f *fakeTagClient) CreateTag(ctx context.Context, in *apipb.CreateTagRequest, _ ...grpc.CallOption) (*apipb.CreateTagResponse, error) {
	f.createCalls++
	return apipb.CreateTagResponse_builder{}.Build(), nil
}

// callTagUpdate drives TagResource.Update with the Plan/State/Identity the
// framework would normally pre-populate.
func callTagUpdate(t *testing.T, r *TagResource, plan, state TagResourceModel) *resource.UpdateResponse {
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

func testTagModel(name string) TagResourceModel {
	return TagResourceModel{
		Name:        types.StringValue(name),
		GroupNames:  types.SetNull(types.StringType),
		GroupIdpIds: types.SetNull(types.StringType),
	}
}

// TestTagUpdateRenamesInPlace is the regression test for a name that used to be
// RequiresReplace: a rename destroyed the tag and recreated it, discarding
// every rule, sync setting and tag-order position attached to it. RenameTag
// preserves all of them.
func TestTagUpdateRenamesInPlace(t *testing.T) {
	fake := &fakeTagClient{}
	r := &TagResource{client: fake}

	resp := callTagUpdate(t, r, testTagModel("prod"), testTagModel("production"))
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	if fake.renameCalls != 1 {
		t.Fatalf("RenameTag calls = %d, want 1", fake.renameCalls)
	}
	if got := fake.lastRenameReq; got.GetTag() != "production" || got.GetNewTag() != "prod" {
		t.Errorf("rename: got (%q -> %q), want (production -> prod)", got.GetTag(), got.GetNewTag())
	}
	if fake.deleteCalls != 0 || fake.createCalls != 0 {
		t.Errorf("a rename must not destroy and recreate the tag; got %d deletes, %d creates", fake.deleteCalls, fake.createCalls)
	}

	var final TagResourceModel
	if diags := resp.State.Get(context.Background(), &final); diags.HasError() {
		t.Fatalf("reading final state: %v", diags)
	}
	if final.Name.ValueString() != "prod" {
		t.Errorf("state name: got %q, want %q", final.Name.ValueString(), "prod")
	}

	var identity TagIdentityModel
	if diags := resp.Identity.Get(context.Background(), &identity); diags.HasError() {
		t.Fatalf("reading identity: %v", diags)
	}
	if identity.Name.ValueString() != "prod" {
		t.Errorf("identity name: got %q, want the new name", identity.Name.ValueString())
	}
}

// TestTagUpdateWithoutRenameSkipsRenameTag checks a group-only change does not
// call RenameTag.
func TestTagUpdateWithoutRenameSkipsRenameTag(t *testing.T) {
	fake := &fakeTagClient{}
	r := &TagResource{client: fake}

	resp := callTagUpdate(t, r, testTagModel("prod"), testTagModel("prod"))
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	if fake.renameCalls != 0 {
		t.Errorf("RenameTag calls = %d, want 0", fake.renameCalls)
	}
}

func TestTagUpdateRenameErrorSurfacesDiagnostic(t *testing.T) {
	fake := &fakeTagClient{renameErr: errors.New("boom")}
	r := &TagResource{client: fake}

	resp := callTagUpdate(t, r, testTagModel("prod"), testTagModel("production"))
	if !resp.Diagnostics.HasError() {
		t.Error("expected an error diagnostic when RenameTag fails")
	}
	if fake.deleteCalls != 0 {
		t.Errorf("a failed rename must not delete the tag; got %d delete calls", fake.deleteCalls)
	}
}

type failingGroupTagClient struct {
	fakeTagClient
}

func (f *failingGroupTagClient) ListGroups(ctx context.Context, in *apipb.ListGroupsRequest, _ ...grpc.CallOption) (*apipb.ListGroupsResponse, error) {
	return nil, errors.New("list groups is down")
}

// TestTagUpdateCommitsRenameBeforeGroupWork is the regression test for a
// rename that succeeded and was then thrown away. RenameTag has no undo, so a
// later group-reconciliation failure must not leave state pointing at the old
// name: the next refresh would look that name up, find nothing, drop the
// resource from state, and leave the renamed tag orphaned.
func TestTagUpdateCommitsRenameBeforeGroupWork(t *testing.T) {
	ctx := context.Background()
	fake := &failingGroupTagClient{}
	r := &TagResource{client: fake}

	plan := testTagModel("prod")
	plan.GroupNames = types.SetValueMust(types.StringType, []attr.Value{types.StringValue("Engineering")})

	resp := callTagUpdate(t, r, plan, testTagModel("production"))
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected the group failure to surface as an error")
	}
	if fake.renameCalls != 1 {
		t.Fatalf("RenameTag calls = %d, want 1", fake.renameCalls)
	}

	var final TagResourceModel
	if diags := resp.State.Get(ctx, &final); diags.HasError() {
		t.Fatalf("reading final state: %v", diags)
	}
	if final.Name.ValueString() != "prod" {
		t.Errorf("state name: got %q, want the new name so the tag is not orphaned", final.Name.ValueString())
	}

	var identity TagIdentityModel
	if diags := resp.Identity.Get(ctx, &identity); diags.HasError() {
		t.Fatalf("reading identity: %v", diags)
	}
	if identity.Name.ValueString() != "prod" {
		t.Errorf("identity name: got %q, want the new name", identity.Name.ValueString())
	}
}
