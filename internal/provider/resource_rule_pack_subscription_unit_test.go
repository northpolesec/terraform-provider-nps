// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// fakeRulePackSubsClient records the ListRulePackSubscriptions request and
// replays a canned response. Any other RPC panics, keeping the test focused.
type fakeRulePackSubsClient struct {
	svcpb.WorkshopServiceClient

	subs    []*apipb.RulePackSubscription
	lastReq *apipb.ListRulePackSubscriptionsRequest

	getSub   *apipb.RulePackSubscription
	getCalls int
}

func (c *fakeRulePackSubsClient) ListRulePackSubscriptions(ctx context.Context, in *apipb.ListRulePackSubscriptionsRequest, opts ...grpc.CallOption) (*apipb.ListRulePackSubscriptionsResponse, error) {
	c.lastReq = in
	return apipb.ListRulePackSubscriptionsResponse_builder{Subscriptions: c.subs}.Build(), nil
}

func (c *fakeRulePackSubsClient) GetRulePackSubscription(ctx context.Context, in *apipb.GetRulePackSubscriptionRequest, opts ...grpc.CallOption) (*apipb.GetRulePackSubscriptionResponse, error) {
	c.getCalls++
	return apipb.GetRulePackSubscriptionResponse_builder{Subscription: c.getSub}.Build(), nil
}

// TestUpdateWithNothingToApplyLeavesNoUnknowns is a regression test for
// "Provider returned invalid result object after apply". Terraform marks the
// computed attributes unknown in the plan as soon as any attribute changes, so
// an Update with no RPC to make must still read the subscription back instead
// of writing those unknowns into state.
func TestUpdateWithNothingToApplyLeavesNoUnknowns(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const materialized = "bddaf69e568d0791e8d1121f5a4c7a61c303d829"
	const latest = "d63f5160cd000d388dee57bed9edbb120d8e0e16"

	fake := &fakeRulePackSubsClient{getSub: apipb.RulePackSubscription_builder{
		Id:                    199,
		RulePackId:            "3b524303-50a9-410d-a25e-3283f68977f5",
		Tags:                  []string{"global"},
		MaterializedCommitSha: materialized,
		LatestCommitSha:       latest,
		SyncStatusCode:        apipb.RulePackSubscriptionSyncStatus_RULE_PACK_SUBSCRIPTION_SYNC_STATUS_SUCCESS,
	}.Build()}
	r := &RulePackSubscriptionResource{client: fake}

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	var identitySchemaResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &identitySchemaResp)

	state := RulePackSubscriptionResourceModel{
		Id:                    types.Int64Value(199),
		RulePackId:            types.StringValue("3b524303-50a9-410d-a25e-3283f68977f5"),
		RulePackTitle:         types.StringNull(),
		Tags:                  types.SetValueMust(types.StringType, []attr.Value{types.StringValue("global")}),
		CommitSha:             types.StringNull(),
		MaterializedCommitSha: types.StringValue(materialized),
		LatestCommitSha:       types.StringValue(latest),
		SyncStatus:            types.StringValue("RULE_PACK_SUBSCRIPTION_SYNC_STATUS_SUCCESS"),
	}

	// commit_sha is newly set to the version that is already materialized: a
	// real config diff with nothing to send to Workshop. Terraform therefore
	// plans the computed attributes as unknown.
	plan := state
	plan.CommitSha = types.StringValue(materialized)
	plan.MaterializedCommitSha = types.StringUnknown()
	plan.LatestCommitSha = types.StringUnknown()
	plan.SyncStatus = types.StringUnknown()

	req := resource.UpdateRequest{
		State: tfsdk.State{Schema: schemaResp.Schema},
		Plan:  tfsdk.Plan{Schema: schemaResp.Schema},
	}
	if diags := req.State.Set(ctx, &state); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	if diags := req.Plan.Set(ctx, &plan); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags)
	}
	resp := &resource.UpdateResponse{
		State:    tfsdk.State{Schema: schemaResp.Schema},
		Identity: &tfsdk.ResourceIdentity{Schema: identitySchemaResp.IdentitySchema},
	}

	r.Update(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned errors: %v", resp.Diagnostics)
	}
	if fake.getCalls != 1 {
		t.Errorf("GetRulePackSubscription called %d times, want 1", fake.getCalls)
	}

	var got RulePackSubscriptionResourceModel
	if diags := resp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("failed to read state: %v", diags)
	}
	for _, tc := range []struct {
		name string
		val  types.String
		want string
	}{
		{"materialized_commit_sha", got.MaterializedCommitSha, materialized},
		{"latest_commit_sha", got.LatestCommitSha, latest},
		{"sync_status", got.SyncStatus, "RULE_PACK_SUBSCRIPTION_SYNC_STATUS_SUCCESS"},
	} {
		if tc.val.IsUnknown() {
			t.Errorf("%s is still unknown after apply", tc.name)
			continue
		}
		if tc.val.ValueString() != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.val.ValueString(), tc.want)
		}
	}
	if got.CommitSha.ValueString() != materialized {
		t.Errorf("commit_sha = %q, want %q", got.CommitSha.ValueString(), materialized)
	}
}

// TestExistingSubscription covers the pre-create duplicate check. Workshop
// allows only one subscription per pack, so this is what turns a second
// resource for the same pack into an actionable error instead of a raw
// server rejection. The filter is asserted because getting it wrong would
// silently return nothing and skip the check entirely.
func TestExistingSubscription(t *testing.T) {
	t.Parallel()

	const packID = "80d661f5-4d9f-4328-bf9f-7022b061065a"

	t.Run("no existing subscription", func(t *testing.T) {
		t.Parallel()
		fake := &fakeRulePackSubsClient{}
		r := &RulePackSubscriptionResource{client: fake}

		got, err := r.existingSubscription(context.Background(), packID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("existingSubscription() = %v, want nil", got)
		}
		if want := `rule_pack_id = "` + packID + `"`; fake.lastReq.GetFilter() != want {
			t.Errorf("filter = %q, want %q", fake.lastReq.GetFilter(), want)
		}
	})

	t.Run("existing subscription is returned", func(t *testing.T) {
		t.Parallel()
		fake := &fakeRulePackSubsClient{subs: []*apipb.RulePackSubscription{
			apipb.RulePackSubscription_builder{Id: 265, RulePackId: packID, Tags: []string{"global"}}.Build(),
		}}
		r := &RulePackSubscriptionResource{client: fake}

		got, err := r.existingSubscription(context.Background(), packID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.GetId() != 265 {
			t.Fatalf("existingSubscription() = %v, want subscription 265", got)
		}
	})
}

// TestResolvePack covers selecting a pack by UUID or by title, including the
// ambiguous-title case that must not silently pick a pack.
func TestResolvePack(t *testing.T) {
	t.Parallel()

	pack := func(id, title string) *apipb.RulePack {
		return apipb.RulePack_builder{Id: id, Title: title}.Build()
	}
	catalog := []*apipb.RulePack{
		pack("uuid-a", "Known Bad Binaries"),
		pack("uuid-b", "Developer Tools"),
		pack("uuid-c", "Developer Tools"),
	}

	tests := []struct {
		name    string
		id      string
		title   string
		wantID  string
		wantErr string
	}{
		{name: "by id", id: "uuid-b", wantID: "uuid-b"},
		{name: "by unique title", title: "Known Bad Binaries", wantID: "uuid-a"},
		{name: "unknown id", id: "uuid-z", wantErr: `no rule pack with id "uuid-z"`},
		{name: "unknown title", title: "Nope", wantErr: `no rule pack titled "Nope"`},
		{name: "ambiguous title", title: "Developer Tools", wantErr: `2 available rule packs are titled "Developer Tools"`},
		// A title that happens to equal another pack's UUID must not match by
		// the wrong field.
		{name: "title is not matched against ids", title: "uuid-a", wantErr: `no rule pack titled "uuid-a"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolvePack(catalog, tc.id, tc.title)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolvePack(_, %q, %q) error = %v, want containing %q", tc.id, tc.title, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePack(_, %q, %q) unexpected error: %v", tc.id, tc.title, err)
			}
			if got.GetId() != tc.wantID {
				t.Errorf("resolvePack(_, %q, %q) = %q, want %q", tc.id, tc.title, got.GetId(), tc.wantID)
			}
		})
	}
}

// TestShouldApplyVersion pins the anti-stomp guard: Terraform only moves a
// subscription's pack version when the operator explicitly named the version
// they reviewed.
func TestShouldApplyVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		commitSha    types.String
		materialized string
		want         bool
	}{
		{"unset never applies", types.StringNull(), "aaa", false},
		{"unknown never applies", types.StringUnknown(), "aaa", false},
		{"matching sha is a no-op", types.StringValue("aaa"), "aaa", false},
		{"newer sha applies", types.StringValue("bbb"), "aaa", true},
		{"unset with drifted server version still does nothing", types.StringNull(), "bbb", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldApplyVersion(tc.commitSha, tc.materialized); got != tc.want {
				t.Errorf("shouldApplyVersion(%v, %q) = %v, want %v", tc.commitSha, tc.materialized, got, tc.want)
			}
		})
	}
}

func TestModifyPlanReplacesWhenTitleIsUnknown(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &RulePackSubscriptionResource{client: &fakeRulePackSubsClient{}}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	state := RulePackSubscriptionResourceModel{
		Id:                    types.Int64Value(42),
		RulePackId:            types.StringValue("pack-a"),
		RulePackTitle:         types.StringValue("Pack A"),
		Tags:                  types.SetValueMust(types.StringType, []attr.Value{types.StringValue("global")}),
		CommitSha:             types.StringNull(),
		MaterializedCommitSha: types.StringValue("aaa"),
		LatestCommitSha:       types.StringValue("aaa"),
		SyncStatus:            types.StringValue("RULE_PACK_SUBSCRIPTION_SYNC_STATUS_SUCCESS"),
	}
	plan := state
	plan.RulePackTitle = types.StringUnknown()

	req := resource.ModifyPlanRequest{
		State: tfsdk.State{Schema: schemaResp.Schema},
		Plan:  tfsdk.Plan{Schema: schemaResp.Schema},
	}
	if diags := req.State.Set(ctx, &state); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	if diags := req.Plan.Set(ctx, &plan); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags)
	}
	resp := &resource.ModifyPlanResponse{Plan: req.Plan}

	r.ModifyPlan(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan returned errors: %v", resp.Diagnostics)
	}
	if len(resp.RequiresReplace) != 1 || !resp.RequiresReplace[0].Equal(path.Root("rule_pack_title")) {
		t.Fatalf("RequiresReplace = %v, want [rule_pack_title]", resp.RequiresReplace)
	}
}

func TestImportState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &RulePackSubscriptionResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	var identitySchemaResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &identitySchemaResp)

	for _, tc := range []struct {
		name        string
		id          string
		useIdentity bool
	}{
		{name: "string id", id: "42"},
		{name: "resource identity", useIdentity: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var identity *tfsdk.ResourceIdentity
			if tc.useIdentity {
				identity = &tfsdk.ResourceIdentity{Schema: identitySchemaResp.IdentitySchema}
				if diags := identity.Set(ctx, RulePackSubscriptionIdentityModel{Id: types.Int64Value(42)}); diags.HasError() {
					t.Fatalf("failed to build identity: %v", diags)
				}
			}
			req := resource.ImportStateRequest{ID: tc.id, Identity: identity}
			resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: schemaResp.Schema}, Identity: identity}
			if diags := resp.State.Set(ctx, RulePackSubscriptionResourceModel{
				Id:                    types.Int64Null(),
				RulePackId:            types.StringNull(),
				RulePackTitle:         types.StringNull(),
				Tags:                  types.SetNull(types.StringType),
				CommitSha:             types.StringNull(),
				MaterializedCommitSha: types.StringNull(),
				LatestCommitSha:       types.StringNull(),
				SyncStatus:            types.StringNull(),
			}); diags.HasError() {
				t.Fatalf("failed to initialize import state: %v", diags)
			}

			r.ImportState(ctx, req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("ImportState returned errors: %v", resp.Diagnostics)
			}
			var got types.Int64
			if diags := resp.State.GetAttribute(ctx, path.Root("id"), &got); diags.HasError() {
				t.Fatalf("failed to read imported id: %v", diags)
			}
			if got.ValueInt64() != 42 {
				t.Fatalf("imported id = %v, want 42", got)
			}
		})
	}
}
