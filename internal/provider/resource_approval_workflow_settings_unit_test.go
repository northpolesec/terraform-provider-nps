// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

type fakeApprovalWorkflowClient struct {
	svcpb.WorkshopServiceClient

	settings   []*apipb.ApprovalWorkflowSettings
	listFilter string

	updated     *apipb.ApprovalWorkflowSettings
	deleteCalls int
	deleteErr   error
}

func (c *fakeApprovalWorkflowClient) ListApprovalWorkflowSettings(ctx context.Context, in *apipb.ListApprovalWorkflowSettingsRequest, _ ...grpc.CallOption) (*apipb.ListApprovalWorkflowSettingsResponse, error) {
	c.listFilter = in.GetFilter()
	return apipb.ListApprovalWorkflowSettingsResponse_builder{ApprovalWorkflowSettings: c.settings}.Build(), nil
}

func (c *fakeApprovalWorkflowClient) UpdateApprovalWorkflowSettings(ctx context.Context, in *apipb.UpdateApprovalWorkflowSettingsRequest, _ ...grpc.CallOption) (*apipb.UpdateApprovalWorkflowSettingsResponse, error) {
	c.updated = in.GetApprovalWorkflowSettings()
	return &apipb.UpdateApprovalWorkflowSettingsResponse{}, nil
}

func (c *fakeApprovalWorkflowClient) DeleteApprovalWorkflowSettings(ctx context.Context, in *apipb.DeleteApprovalWorkflowSettingsRequest, _ ...grpc.CallOption) (*apipb.DeleteApprovalWorkflowSettingsResponse, error) {
	c.deleteCalls++
	if c.deleteErr != nil {
		return nil, c.deleteErr
	}
	return &apipb.DeleteApprovalWorkflowSettingsResponse{}, nil
}

func stringList(t *testing.T, values ...string) types.List {
	t.Helper()
	if values == nil {
		// A nil slice converts to a null list, not an empty one.
		values = []string{}
	}
	list, diags := types.ListValueFrom(context.Background(), types.StringType, values)
	if diags.HasError() {
		t.Fatalf("building list: %v", diags)
	}
	return list
}

// TestApprovalWorkflowRoundtrip asserts every arm of the workflow oneof
// survives model -> proto -> model with its own fields intact, including the
// approver oneof nested inside the designated-approver arm.
func TestApprovalWorkflowRoundtrip(t *testing.T) {
	ctx := context.Background()

	base := func() ApprovalWorkflowSettingsResourceModel {
		return ApprovalWorkflowSettingsResourceModel{
			Tag:                types.StringValue("dev"),
			ApprovalRuleType:   types.StringValue("CDHASH"),
			NotificationMethod: types.StringValue("SLACK"),
		}
	}

	for _, c := range []struct {
		name  string
		model func() ApprovalWorkflowSettingsResourceModel
		check func(t *testing.T, s *apipb.ApprovalWorkflowSettings, got ApprovalWorkflowSettingsResourceModel)
	}{
		{
			name:  "no block is the none workflow",
			model: base,
			check: func(t *testing.T, s *apipb.ApprovalWorkflowSettings, got ApprovalWorkflowSettingsResourceModel) {
				if s.WhichWorkflow() != apipb.ApprovalWorkflowSettings_None_case {
					t.Errorf("workflow = %v, want the none arm", s.WhichWorkflow())
				}
				if got.SelfService != nil || got.DesignatedApprover != nil || got.SocialVoting != nil {
					t.Errorf("got a workflow block back: %+v", got)
				}
			},
		},
		{
			name: "self service",
			model: func() ApprovalWorkflowSettingsResourceModel {
				m := base()
				m.SelfService = &ApprovalWorkflowSelfServiceModel{RequireJustification: types.BoolValue(true)}
				return m
			},
			check: func(t *testing.T, s *apipb.ApprovalWorkflowSettings, got ApprovalWorkflowSettingsResourceModel) {
				if !s.GetSelfService().GetRequireJustification() {
					t.Error("require_justification was not sent")
				}
				if got.SelfService == nil || !got.SelfService.RequireJustification.ValueBool() {
					t.Errorf("self_service = %+v, want require_justification true", got.SelfService)
				}
			},
		},
		{
			name: "designated approver by tag",
			model: func() ApprovalWorkflowSettingsResourceModel {
				m := base()
				m.DesignatedApprover = &ApprovalWorkflowDesignatedApproverModel{
					ApproverTag:          types.StringValue("security"),
					ApproverEmails:       types.ListNull(types.StringType),
					ApproverIsManager:    types.BoolNull(),
					Threshold:            types.Int64Value(2),
					ChatChannel:          types.StringValue("#approvals"),
					RequireJustification: types.BoolValue(true),
					AllowTagApproval:     types.BoolValue(true),
				}
				return m
			},
			check: func(t *testing.T, s *apipb.ApprovalWorkflowSettings, got ApprovalWorkflowSettingsResourceModel) {
				da := s.GetDesignatedApprover()
				if da.WhichApprover() != apipb.DesignatedApproverWorkflowSettings_Tag_case {
					t.Fatalf("approver = %v, want the tag arm", da.WhichApprover())
				}
				if da.GetTag().GetTag() != "security" || da.GetTag().GetThreshold() != 2 {
					t.Errorf("approver tag = %q/%d, want security/2", da.GetTag().GetTag(), da.GetTag().GetThreshold())
				}
				if da.GetChatChannel() != "#approvals" || !da.GetAllowTagApproval() {
					t.Errorf("chat_channel/allow_tag_approval = %q/%v", da.GetChatChannel(), da.GetAllowTagApproval())
				}
				if got.DesignatedApprover.ApproverTag.ValueString() != "security" ||
					got.DesignatedApprover.Threshold.ValueInt64() != 2 ||
					got.DesignatedApprover.ChatChannel.ValueString() != "#approvals" {
					t.Errorf("designated_approver = %+v", got.DesignatedApprover)
				}
				if !got.DesignatedApprover.ApproverEmails.IsNull() || !got.DesignatedApprover.ApproverIsManager.IsNull() {
					t.Errorf("unused approver arms should stay null: %+v", got.DesignatedApprover)
				}
			},
		},
		{
			name: "designated approver by emails",
			model: func() ApprovalWorkflowSettingsResourceModel {
				m := base()
				m.DesignatedApprover = &ApprovalWorkflowDesignatedApproverModel{
					ApproverTag:       types.StringNull(),
					ApproverEmails:    stringList(t, "a@example.com", "b@example.com"),
					ApproverIsManager: types.BoolNull(),
					Threshold:         types.Int64Value(1),
				}
				return m
			},
			check: func(t *testing.T, s *apipb.ApprovalWorkflowSettings, got ApprovalWorkflowSettingsResourceModel) {
				da := s.GetDesignatedApprover()
				if da.WhichApprover() != apipb.DesignatedApproverWorkflowSettings_Emails_case {
					t.Fatalf("approver = %v, want the emails arm", da.WhichApprover())
				}
				if emails := da.GetEmails().GetApproverEmails(); len(emails) != 2 || emails[0] != "a@example.com" {
					t.Errorf("approver_emails = %v", emails)
				}
				if n := len(got.DesignatedApprover.ApproverEmails.Elements()); n != 2 {
					t.Errorf("approver_emails came back with %d entries, want 2", n)
				}
				if got.DesignatedApprover.Threshold.ValueInt64() != 1 {
					t.Errorf("threshold = %d, want 1", got.DesignatedApprover.Threshold.ValueInt64())
				}
			},
		},
		{
			name: "designated approver is manager",
			model: func() ApprovalWorkflowSettingsResourceModel {
				m := base()
				m.DesignatedApprover = &ApprovalWorkflowDesignatedApproverModel{
					ApproverTag:       types.StringNull(),
					ApproverEmails:    types.ListNull(types.StringType),
					ApproverIsManager: types.BoolValue(true),
					Threshold:         types.Int64Null(),
				}
				return m
			},
			check: func(t *testing.T, s *apipb.ApprovalWorkflowSettings, got ApprovalWorkflowSettingsResourceModel) {
				if s.GetDesignatedApprover().WhichApprover() != apipb.DesignatedApproverWorkflowSettings_Manager_case {
					t.Fatalf("approver = %v, want the manager arm", s.GetDesignatedApprover().WhichApprover())
				}
				if !got.DesignatedApprover.ApproverIsManager.ValueBool() {
					t.Error("approver_is_manager did not come back true")
				}
				if !got.DesignatedApprover.Threshold.IsNull() {
					t.Errorf("threshold = %v, want null for the manager arm", got.DesignatedApprover.Threshold)
				}
			},
		},
		{
			name: "social voting",
			model: func() ApprovalWorkflowSettingsResourceModel {
				m := base()
				m.SocialVoting = &ApprovalWorkflowSocialVotingModel{
					LocalThreshold:          types.Int64Value(2),
					TagThreshold:            types.Int64Value(5),
					TagsToConsiderVotesFrom: stringList(t, "dev", "sre"),
					RequireJustification:    types.BoolValue(false),
				}
				return m
			},
			check: func(t *testing.T, s *apipb.ApprovalWorkflowSettings, got ApprovalWorkflowSettingsResourceModel) {
				sv := s.GetSocialVoting()
				if sv.GetLocalThreshold() != 2 || sv.GetTagThreshold() != 5 {
					t.Errorf("thresholds = %d/%d, want 2/5", sv.GetLocalThreshold(), sv.GetTagThreshold())
				}
				if tags := sv.GetTagsToConsiderVotesFrom(); len(tags) != 2 || tags[1] != "sre" {
					t.Errorf("tags_to_consider_votes_from = %v", tags)
				}
				if got.SocialVoting.TagThreshold.ValueInt64() != 5 ||
					len(got.SocialVoting.TagsToConsiderVotesFrom.Elements()) != 2 {
					t.Errorf("social_voting = %+v", got.SocialVoting)
				}
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var diags diag.Diagnostics
			model := c.model()
			s := approvalWorkflowModelToProto(ctx, &model, &diags)
			if diags.HasError() {
				t.Fatalf("model->proto: %v", diags)
			}
			if s.GetTag() != "dev" || s.GetApprovalRuleType() != apipb.RuleType_CDHASH {
				t.Errorf("tag/rule type = %q/%v, want dev/CDHASH", s.GetTag(), s.GetApprovalRuleType())
			}
			if s.GetNotificationMethod() != apipb.ApprovalWorkflowSettings_NOTIFICATION_METHOD_SLACK {
				t.Errorf("notification_method = %v, want SLACK", s.GetNotificationMethod())
			}

			got := approvalWorkflowProtoToModel(ctx, &model, s, &diags)
			if diags.HasError() {
				t.Fatalf("proto->model: %v", diags)
			}
			if got.NotificationMethod.ValueString() != "SLACK" {
				t.Errorf("notification_method = %q, want the configured spelling SLACK", got.NotificationMethod.ValueString())
			}
			c.check(t, s, got)
		})
	}
}

// TestApprovalWorkflowConfigValidation covers the combinations the server
// rejects, so they fail the plan instead of the apply.
func TestApprovalWorkflowConfigValidation(t *testing.T) {
	ctx := context.Background()

	var sResp resource.SchemaResponse
	(&ApprovalWorkflowSettingsResource{}).Schema(ctx, resource.SchemaRequest{}, &sResp)

	emails := stringList(t, "a@example.com", "b@example.com")

	for _, c := range []struct {
		name    string
		model   ApprovalWorkflowSettingsResourceModel
		notify  bool // set notification_method, which chat_channel requires
		wantErr bool
	}{
		{
			name:  "no workflow block",
			model: ApprovalWorkflowSettingsResourceModel{},
		},
		{
			name: "two workflow blocks",
			model: ApprovalWorkflowSettingsResourceModel{
				SelfService:  &ApprovalWorkflowSelfServiceModel{},
				SocialVoting: &ApprovalWorkflowSocialVotingModel{LocalThreshold: types.Int64Value(1), TagThreshold: types.Int64Value(1)},
			},
			wantErr: true,
		},
		{
			name: "approver tag with threshold",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
					ApproverTag: types.StringValue("security"),
					Threshold:   types.Int64Value(2),
				},
			},
		},
		{
			name: "approver tag without threshold",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
					ApproverTag: types.StringValue("security"),
				},
			},
			wantErr: true,
		},
		{
			name: "no approver arm",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{Threshold: types.Int64Value(1)},
			},
			wantErr: true,
		},
		{
			name: "two approver arms",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
					ApproverTag:    types.StringValue("security"),
					ApproverEmails: emails,
					Threshold:      types.Int64Value(1),
				},
			},
			wantErr: true,
		},
		{
			name: "threshold above the email count",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
					ApproverEmails: emails,
					Threshold:      types.Int64Value(3),
				},
			},
			wantErr: true,
		},
		{
			name: "chat channel without a notification method",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
					ApproverTag: types.StringValue("security"),
					Threshold:   types.Int64Value(1),
					ChatChannel: types.StringValue("#approvals"),
				},
			},
			wantErr: true,
		},
		{
			name: "manager with a chat channel",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
					ApproverIsManager: types.BoolValue(true),
					ChatChannel:       types.StringValue("#approvals"),
				},
			},
			notify:  true,
			wantErr: true,
		},
		{
			name: "manager with a threshold",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
					ApproverIsManager: types.BoolValue(true),
					Threshold:         types.Int64Value(1),
				},
			},
			wantErr: true,
		},
		{
			name: "manager alone",
			model: ApprovalWorkflowSettingsResourceModel{
				DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
					ApproverIsManager: types.BoolValue(true),
				},
			},
		},
		{
			name: "social voting without a local threshold",
			model: ApprovalWorkflowSettingsResourceModel{
				SocialVoting: &ApprovalWorkflowSocialVotingModel{TagThreshold: types.Int64Value(3)},
			},
			wantErr: true,
		},
		{
			name: "tag threshold below the local threshold",
			model: ApprovalWorkflowSettingsResourceModel{
				SocialVoting: &ApprovalWorkflowSocialVotingModel{
					LocalThreshold: types.Int64Value(4),
					TagThreshold:   types.Int64Value(3),
				},
			},
			wantErr: true,
		},
		{
			name: "social voting thresholds in order",
			model: ApprovalWorkflowSettingsResourceModel{
				SocialVoting: &ApprovalWorkflowSocialVotingModel{
					LocalThreshold: types.Int64Value(3),
					TagThreshold:   types.Int64Value(3),
				},
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			model := c.model
			model.Tag = types.StringValue("dev")
			model.ApprovalRuleType = types.StringValue("CDHASH")
			if model.NotificationMethod.IsNull() && c.notify {
				model.NotificationMethod = types.StringValue("SLACK")
			}
			// A zero-value types.List carries no element type, which the
			// config cannot hold; the cases above only set the lists they
			// care about.
			nullList := func(l types.List) types.List {
				if l.ElementType(ctx) == nil {
					return types.ListNull(types.StringType)
				}
				return l
			}
			if da := model.DesignatedApprover; da != nil {
				da.ApproverEmails = nullList(da.ApproverEmails)
			}
			if sv := model.SocialVoting; sv != nil {
				sv.TagsToConsiderVotesFrom = nullList(sv.TagsToConsiderVotesFrom)
			}

			// tfsdk.Config has no Set; build the value through a State and
			// hand the raw object to the config under the same schema.
			raw := tfsdk.State{Schema: sResp.Schema}
			if diags := raw.Set(ctx, model); diags.HasError() {
				t.Fatalf("building config: %v", diags)
			}
			cfg := tfsdk.Config{Schema: sResp.Schema, Raw: raw.Raw}

			resp := &resource.ValidateConfigResponse{}
			for _, v := range (&ApprovalWorkflowSettingsResource{}).ConfigValidators(ctx) {
				v.ValidateResource(ctx, resource.ValidateConfigRequest{Config: cfg}, resp)
			}
			if got := resp.Diagnostics.HasError(); got != c.wantErr {
				t.Errorf("HasError = %v, want %v (diags: %v)", got, c.wantErr, resp.Diagnostics)
			}
		})
	}
}

// TestApprovalWorkflowReadKeepsDefaultedVoteTagsNull guards the refresh loop:
// the server fills tags_to_consider_votes_from with the workflow's own tag, so
// reading it straight back would diff against a configuration that never set
// it.
func TestApprovalWorkflowReadKeepsDefaultedVoteTagsNull(t *testing.T) {
	ctx := context.Background()

	read := func(prior ApprovalWorkflowSettingsResourceModel, voteTags []string) ApprovalWorkflowSettingsResourceModel {
		t.Helper()
		r := &ApprovalWorkflowSettingsResource{client: &fakeApprovalWorkflowClient{
			settings: []*apipb.ApprovalWorkflowSettings{
				apipb.ApprovalWorkflowSettings_builder{
					Tag:              "dev",
					ApprovalRuleType: apipb.RuleType_CDHASH,
					SocialVoting: apipb.SocialVotingWorkflowSettings_builder{
						LocalThreshold:          2,
						TagThreshold:            5,
						TagsToConsiderVotesFrom: voteTags,
					}.Build(),
				}.Build(),
			},
		}}

		var sResp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sResp)
		var iResp resource.IdentitySchemaResponse
		r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)

		req := resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema}}
		if diags := req.State.Set(ctx, prior); diags.HasError() {
			t.Fatalf("building state: %v", diags)
		}
		resp := &resource.ReadResponse{
			State:    tfsdk.State{Schema: sResp.Schema},
			Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
		}
		r.Read(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("read: %v", resp.Diagnostics)
		}
		var got ApprovalWorkflowSettingsResourceModel
		if diags := resp.State.Get(ctx, &got); diags.HasError() {
			t.Fatalf("reading state: %v", diags)
		}
		return got
	}

	prior := ApprovalWorkflowSettingsResourceModel{
		Tag:                types.StringValue("dev"),
		ApprovalRuleType:   types.StringValue("CDHASH"),
		NotificationMethod: types.StringNull(),
		SocialVoting: &ApprovalWorkflowSocialVotingModel{
			LocalThreshold:          types.Int64Value(2),
			TagThreshold:            types.Int64Value(5),
			TagsToConsiderVotesFrom: types.ListNull(types.StringType),
		},
	}

	got := read(prior, []string{"dev"})
	if !got.SocialVoting.TagsToConsiderVotesFrom.IsNull() {
		t.Errorf("tags_to_consider_votes_from = %v, want null when the server only echoed the default",
			got.SocialVoting.TagsToConsiderVotesFrom)
	}
	if !got.NotificationMethod.IsNull() {
		t.Errorf("notification_method = %v, want null when the server reports UNSPECIFIED", got.NotificationMethod)
	}

	// An explicitly empty list asks for the same default, so it must survive
	// as an empty list rather than becoming the tag the server filled in.
	empty := prior
	empty.SocialVoting = &ApprovalWorkflowSocialVotingModel{
		LocalThreshold:          types.Int64Value(2),
		TagThreshold:            types.Int64Value(5),
		TagsToConsiderVotesFrom: stringList(t),
	}
	got = read(empty, []string{"dev"})
	if got.SocialVoting.TagsToConsiderVotesFrom.IsNull() || len(got.SocialVoting.TagsToConsiderVotesFrom.Elements()) != 0 {
		t.Errorf("tags_to_consider_votes_from = %v, want the configured empty list",
			got.SocialVoting.TagsToConsiderVotesFrom)
	}

	// A tag the configuration did not set is real drift and must surface.
	got = read(prior, []string{"dev", "sre"})
	if n := len(got.SocialVoting.TagsToConsiderVotesFrom.Elements()); n != 2 {
		t.Errorf("tags_to_consider_votes_from has %d entries, want the 2 the server reported", n)
	}
}

// TestApprovalWorkflowReadRemovesMissing checks that a tag whose workflow was
// deleted outside Terraform leaves state instead of erroring, and that the
// lookup is filtered to that one tag.
func TestApprovalWorkflowReadRemovesMissing(t *testing.T) {
	ctx := context.Background()
	fake := &fakeApprovalWorkflowClient{}
	r := &ApprovalWorkflowSettingsResource{client: fake}

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	var iResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)

	req := resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema}}
	if diags := req.State.Set(ctx, ApprovalWorkflowSettingsResourceModel{
		Tag:              types.StringValue("dev"),
		ApprovalRuleType: types.StringValue("CDHASH"),
	}); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}
	resp := &resource.ReadResponse{
		State:    tfsdk.State{Schema: sResp.Schema},
		Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
	}
	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("read: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state was kept, want the resource removed")
	}
	if want := `tag = "dev"`; fake.listFilter != want {
		t.Errorf("list filter = %q, want %q", fake.listFilter, want)
	}
}

// TestApprovalWorkflowDeleteToleratesMissing keeps a destroy from failing when
// the workflow is already gone.
func TestApprovalWorkflowDeleteToleratesMissing(t *testing.T) {
	ctx := context.Background()
	fake := &fakeApprovalWorkflowClient{deleteErr: status.Error(codes.NotFound, "record not found")}
	r := &ApprovalWorkflowSettingsResource{client: fake}

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)

	req := resource.DeleteRequest{State: tfsdk.State{Schema: sResp.Schema}}
	if diags := req.State.Set(ctx, ApprovalWorkflowSettingsResourceModel{
		Tag:              types.StringValue("dev"),
		ApprovalRuleType: types.StringValue("CDHASH"),
	}); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}
	resp := &resource.DeleteResponse{State: tfsdk.State{Schema: sResp.Schema}}
	r.Delete(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("delete: %v", resp.Diagnostics)
	}
	if fake.deleteCalls != 1 {
		t.Errorf("DeleteApprovalWorkflowSettings called %d times, want 1", fake.deleteCalls)
	}
}

// TestApprovalWorkflowReadKeepsUnsetBoolsNull guards the refresh loop for the
// presence-less booleans: the server cannot tell an omitted
// require_justification from an explicit false, so reading false back
// verbatim would diff against a configuration that never set it. The shipped
// global example omits allow_tag_approval, which is exactly this case.
func TestApprovalWorkflowReadKeepsUnsetBoolsNull(t *testing.T) {
	ctx := context.Background()

	read := func(prior ApprovalWorkflowSettingsResourceModel) ApprovalWorkflowSettingsResourceModel {
		t.Helper()
		r := &ApprovalWorkflowSettingsResource{client: &fakeApprovalWorkflowClient{
			settings: []*apipb.ApprovalWorkflowSettings{
				apipb.ApprovalWorkflowSettings_builder{
					Tag:              "dev",
					ApprovalRuleType: apipb.RuleType_CDHASH,
					DesignatedApprover: apipb.DesignatedApproverWorkflowSettings_builder{
						Tag: apipb.DesignatedApproverTag_builder{Tag: "security", Threshold: 2}.Build(),
						// Both booleans unset, so the server reports false.
					}.Build(),
				}.Build(),
			},
		}}

		var sResp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sResp)
		var iResp resource.IdentitySchemaResponse
		r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)

		req := resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema}}
		if diags := req.State.Set(ctx, prior); diags.HasError() {
			t.Fatalf("building state: %v", diags)
		}
		resp := &resource.ReadResponse{
			State:    tfsdk.State{Schema: sResp.Schema},
			Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
		}
		r.Read(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("read: %v", resp.Diagnostics)
		}
		var got ApprovalWorkflowSettingsResourceModel
		if diags := resp.State.Get(ctx, &got); diags.HasError() {
			t.Fatalf("reading state: %v", diags)
		}
		return got
	}

	prior := func(allowTagApproval types.Bool) ApprovalWorkflowSettingsResourceModel {
		return ApprovalWorkflowSettingsResourceModel{
			Tag:                types.StringValue("dev"),
			ApprovalRuleType:   types.StringValue("CDHASH"),
			NotificationMethod: types.StringNull(),
			DesignatedApprover: &ApprovalWorkflowDesignatedApproverModel{
				ApproverTag:      types.StringValue("security"),
				ApproverEmails:   types.ListNull(types.StringType),
				Threshold:        types.Int64Value(2),
				AllowTagApproval: allowTagApproval,
			},
		}
	}

	got := read(prior(types.BoolNull()))
	if !got.DesignatedApprover.AllowTagApproval.IsNull() {
		t.Errorf("allow_tag_approval = %v, want null when the configuration never set it",
			got.DesignatedApprover.AllowTagApproval)
	}
	if !got.DesignatedApprover.RequireJustification.IsNull() {
		t.Errorf("require_justification = %v, want null when the configuration never set it",
			got.DesignatedApprover.RequireJustification)
	}

	// An explicit false is a real configured value and must survive as false.
	got = read(prior(types.BoolValue(false)))
	if got.DesignatedApprover.AllowTagApproval.IsNull() || got.DesignatedApprover.AllowTagApproval.ValueBool() {
		t.Errorf("allow_tag_approval = %v, want an explicit false", got.DesignatedApprover.AllowTagApproval)
	}
}
