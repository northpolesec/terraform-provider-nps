// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"
	"google.golang.org/protobuf/proto"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &ApprovalWorkflowSettingsResource{}
var _ resource.ResourceWithConfigure = &ApprovalWorkflowSettingsResource{}
var _ resource.ResourceWithImportState = &ApprovalWorkflowSettingsResource{}
var _ resource.ResourceWithIdentity = &ApprovalWorkflowSettingsResource{}
var _ resource.ResourceWithConfigValidators = &ApprovalWorkflowSettingsResource{}

func NewApprovalWorkflowSettingsResource() resource.Resource {
	return &ApprovalWorkflowSettingsResource{}
}

type ApprovalWorkflowSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type ApprovalWorkflowSettingsIdentityModel struct {
	Tag types.String `tfsdk:"tag"`
}

type ApprovalWorkflowSettingsResourceModel struct {
	Tag                types.String `tfsdk:"tag"`
	ApprovalRuleType   types.String `tfsdk:"approval_rule_type"`
	NotificationMethod types.String `tfsdk:"notification_method"`

	SelfService        *ApprovalWorkflowSelfServiceModel        `tfsdk:"self_service"`
	DesignatedApprover *ApprovalWorkflowDesignatedApproverModel `tfsdk:"designated_approver"`
	SocialVoting       *ApprovalWorkflowSocialVotingModel       `tfsdk:"social_voting"`
}

type ApprovalWorkflowSelfServiceModel struct {
	RequireJustification types.Bool `tfsdk:"require_justification"`
}

type ApprovalWorkflowDesignatedApproverModel struct {
	ApproverTag          types.String `tfsdk:"approver_tag"`
	ApproverEmails       types.List   `tfsdk:"approver_emails"`
	ApproverIsManager    types.Bool   `tfsdk:"approver_is_manager"`
	Threshold            types.Int64  `tfsdk:"threshold"`
	ChatChannel          types.String `tfsdk:"chat_channel"`
	RequireJustification types.Bool   `tfsdk:"require_justification"`
	AllowTagApproval     types.Bool   `tfsdk:"allow_tag_approval"`
}

type ApprovalWorkflowSocialVotingModel struct {
	LocalThreshold          types.Int64 `tfsdk:"local_threshold"`
	TagThreshold            types.Int64 `tfsdk:"tag_threshold"`
	TagsToConsiderVotesFrom types.List  `tfsdk:"tags_to_consider_votes_from"`
	RequireJustification    types.Bool  `tfsdk:"require_justification"`
}

// notificationMethodPrefix is stripped from NotificationMethod values in HCL:
// users write SLACK, the proto says NOTIFICATION_METHOD_SLACK. Both spellings
// are accepted.
const notificationMethodPrefix = "NOTIFICATION_METHOD_"

// approvalRuleTypeValues are the rule types an approval may produce. The
// server rejects every other RuleType, so listing them here fails the plan
// instead of the apply.
var approvalRuleTypeValues = []string{"BINARY", "CDHASH", "SIGNINGID"}

func (r *ApprovalWorkflowSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_approval_workflow_settings"
}

func (r *ApprovalWorkflowSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_approval_workflow_settings resource manages the approval workflow for a single tag: how a user gets a blocked binary approved. A user is offered the workflow of the first of their tags that has one, in tag order, falling back to the tag named global. Exactly one workflow block may be set; with no workflow block the tag has no approval workflow, which also stops a lower-precedence tag's workflow from applying to its users.",
		MarkdownDescription: "The `nps_workshop_approval_workflow_settings` resource manages the approval workflow for a single tag: how a user gets a blocked binary approved. A user is offered the workflow of the first of their tags that has one, in tag order, falling back to the tag named `global`. Exactly one workflow block may be set; with no workflow block the tag has no approval workflow, which also stops a lower-precedence tag's workflow from applying to its users.",

		Attributes: map[string]schema.Attribute{
			"tag": schema.StringAttribute{
				Description:         "The tag whose approval workflow this resource manages. The tag must already exist in Workshop. Use global for the fleet-wide fallback workflow. Changing the tag forces replacement. May contain only letters, digits, periods, colons, hyphens, and underscores (max 42 characters).",
				MarkdownDescription: "The tag whose approval workflow this resource manages. The tag must already exist in Workshop. Use `global` for the fleet-wide fallback workflow. Changing the tag forces replacement. May contain only letters, digits, periods, colons, hyphens, and underscores (max 42 characters).",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, tagNameMaxLen),
					stringvalidator.RegexMatches(
						tagNameRegex,
						"must contain only letters, digits, periods, colons, hyphens, and underscores",
					),
				},
			},
			"approval_rule_type": schema.StringAttribute{
				Description:         "The type of rule a successful approval creates. The possible values are: BINARY, CDHASH, and SIGNINGID. Required even when no workflow block is set.",
				MarkdownDescription: "The type of rule a successful approval creates. The possible values are: `BINARY`, `CDHASH`, and `SIGNINGID`. Required even when no workflow block is set.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(approvalRuleTypeValues...),
				},
			},
			"notification_method": schema.StringAttribute{
				Description:         "How requestors and approvers are notified. The possible values are: NONE and SLACK. The NOTIFICATION_METHOD_-prefixed spellings are accepted as aliases.",
				MarkdownDescription: "How requestors and approvers are notified. The possible values are: `NONE` and `SLACK`. The `NOTIFICATION_METHOD_`-prefixed spellings are accepted as aliases.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumAcceptedValues(apipb.ApprovalWorkflowSettings_NotificationMethod(0).Descriptor(), notificationMethodPrefix)...),
				},
				// Suppresses spelling-only diffs between the bare and prefixed forms.
				PlanModifiers: []planmodifier.String{
					enumForm(notificationMethodPrefix),
				},
			},
		},

		Blocks: map[string]schema.Block{
			"self_service": schema.SingleNestedBlock{
				Description:         "Users approve their own requests. Mutually exclusive with the other workflow blocks.",
				MarkdownDescription: "Users approve their own requests. Mutually exclusive with the other workflow blocks.",
				Attributes: map[string]schema.Attribute{
					"require_justification": schema.BoolAttribute{
						Description:         "Whether the requestor must provide a justification.",
						MarkdownDescription: "Whether the requestor must provide a justification.",
						Optional:            true,
					},
				},
			},
			"designated_approver": schema.SingleNestedBlock{
				Description:         "Named approvers decide the request. Exactly one of approver_tag, approver_emails, or approver_is_manager must be set. Mutually exclusive with the other workflow blocks.",
				MarkdownDescription: "Named approvers decide the request. Exactly one of `approver_tag`, `approver_emails`, or `approver_is_manager` must be set. Mutually exclusive with the other workflow blocks.",
				Attributes: map[string]schema.Attribute{
					"approver_tag": schema.StringAttribute{
						Description:         "Tag whose users may approve. threshold must not exceed the number of users carrying the tag.",
						MarkdownDescription: "Tag whose users may approve. `threshold` must not exceed the number of users carrying the tag.",
						Optional:            true,
						Validators: []validator.String{
							stringvalidator.LengthBetween(1, tagNameMaxLen),
							stringvalidator.RegexMatches(
								tagNameRegex,
								"must contain only letters, digits, periods, colons, hyphens, and underscores",
							),
						},
					},
					"approver_emails": schema.ListAttribute{
						Description:         "Email addresses that may approve.",
						MarkdownDescription: "Email addresses that may approve.",
						Optional:            true,
						ElementType:         types.StringType,
					},
					"approver_is_manager": schema.BoolAttribute{
						Description:         "Set to true to route the request to the requestor's manager. The chat bot opens a group chat with the manager, so chat_channel and threshold must be left unset.",
						MarkdownDescription: "Set to `true` to route the request to the requestor's manager. The chat bot opens a group chat with the manager, so `chat_channel` and `threshold` must be left unset.",
						Optional:            true,
					},
					"threshold": schema.Int64Attribute{
						Description:         "Number of approvals required. Required with approver_tag or approver_emails.",
						MarkdownDescription: "Number of approvals required. Required with `approver_tag` or `approver_emails`.",
						Optional:            true,
						Validators: []validator.Int64{
							// The proto field is a uint32; without the ceiling the
							// conversion silently wraps (4294967296 becomes 0).
							int64validator.Between(1, int64(math.MaxUint32)),
						},
					},
					"chat_channel": schema.StringAttribute{
						Description:         "Chat channel notifications are sent to, which requires notification_method. A Slack channel is 1 to 21 lowercase letters, digits, and non-repeating interior hyphens, with an optional leading #. Leave unset to have the chat bot ask the requestor to pick an approver.",
						MarkdownDescription: "Chat channel notifications are sent to, which requires `notification_method`. A Slack channel is 1 to 21 lowercase letters, digits, and non-repeating interior hyphens, with an optional leading `#`. Leave unset to have the chat bot ask the requestor to pick an approver.",
						Optional:            true,
					},
					"require_justification": schema.BoolAttribute{
						Description:         "Whether the requestor must provide a justification.",
						MarkdownDescription: "Whether the requestor must provide a justification.",
						Optional:            true,
					},
					"allow_tag_approval": schema.BoolAttribute{
						Description:         "Whether the deciding approval may create a rule for every host carrying the workflow's tag rather than only the requestor's hosts. On the global workflow this creates a fleet-wide rule.",
						MarkdownDescription: "Whether the deciding approval may create a rule for every host carrying the workflow's tag rather than only the requestor's hosts. On the `global` workflow this creates a fleet-wide rule.",
						Optional:            true,
					},
				},
			},
			"social_voting": schema.SingleNestedBlock{
				Description:         "Peers vote on the request. Mutually exclusive with the other workflow blocks.",
				MarkdownDescription: "Peers vote on the request. Mutually exclusive with the other workflow blocks.",
				Attributes: map[string]schema.Attribute{
					"local_threshold": schema.Int64Attribute{
						Description:         "Votes required to approve the software for the requestor alone. Required when the block is present.",
						MarkdownDescription: "Votes required to approve the software for the requestor alone. Required when the block is present.",
						Optional:            true,
						Validators: []validator.Int64{
							// The proto field is a uint32; without the ceiling the
							// conversion silently wraps (4294967296 becomes 0).
							int64validator.Between(1, int64(math.MaxUint32)),
						},
					},
					"tag_threshold": schema.Int64Attribute{
						Description:         "Votes required to approve the software for every user the workflow's tag covers. Required when the block is present, and must be at least local_threshold.",
						MarkdownDescription: "Votes required to approve the software for every user the workflow's tag covers. Required when the block is present, and must be at least `local_threshold`.",
						Optional:            true,
						Validators: []validator.Int64{
							// The proto field is a uint32; without the ceiling the
							// conversion silently wraps (4294967296 becomes 0).
							int64validator.Between(1, int64(math.MaxUint32)),
						},
					},
					"tags_to_consider_votes_from": schema.ListAttribute{
						Description:         "Tags whose users' votes count toward the thresholds. Defaults to the workflow's own tag.",
						MarkdownDescription: "Tags whose users' votes count toward the thresholds. Defaults to the workflow's own tag.",
						Optional:            true,
						ElementType:         types.StringType,
					},
					"require_justification": schema.BoolAttribute{
						Description:         "Whether the requestor must provide a justification.",
						MarkdownDescription: "Whether the requestor must provide a justification.",
						Optional:            true,
					},
				},
			},
		},
	}
}

func (r *ApprovalWorkflowSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	pd, ok := req.ProviderData.(*NPSProviderResourceData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected NPSProviderResourceData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = pd.Client
}

// ConfigValidators mirrors the server-side workflow validation so a bad
// combination fails the plan instead of the apply.
func (r *ApprovalWorkflowSettingsResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		utils.ConfigValidatorFunc("Validate approval workflow blocks", func(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
			var data ApprovalWorkflowSettingsResourceModel
			resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
			if resp.Diagnostics.HasError() {
				return
			}

			// The workflow is a proto oneof: a second block would silently
			// overwrite the first.
			var set []string
			if data.SelfService != nil {
				set = append(set, "self_service")
			}
			if data.DesignatedApprover != nil {
				set = append(set, "designated_approver")
			}
			if data.SocialVoting != nil {
				set = append(set, "social_voting")
			}
			if len(set) > 1 {
				resp.Diagnostics.AddError(
					"Conflicting approval workflows",
					fmt.Sprintf("Only one workflow block may be set, got: %s.", strings.Join(set, ", ")),
				)
				return
			}

			validateDesignatedApproverBlock(data.DesignatedApprover, data.NotificationMethod, &resp.Diagnostics)
			validateSocialVotingBlock(data.SocialVoting, &resp.Diagnostics)
		}),
	}
}

// validateDesignatedApproverBlock checks the approver oneof and the threshold
// rules. Unknown values are skipped: they resolve during apply, and failing
// the plan on them would reject a configuration that is perfectly valid.
func validateDesignatedApproverBlock(da *ApprovalWorkflowDesignatedApproverModel, notificationMethod types.String, diags *diag.Diagnostics) {
	if da == nil {
		return
	}
	root := path.Root("designated_approver")

	var set []string
	if isSetString(da.ApproverTag) {
		set = append(set, "approver_tag")
	}
	if isSetList(da.ApproverEmails) {
		set = append(set, "approver_emails")
	}
	manager := !da.ApproverIsManager.IsNull() && !da.ApproverIsManager.IsUnknown() && da.ApproverIsManager.ValueBool()
	if manager {
		set = append(set, "approver_is_manager")
	}

	if len(set) != 1 {
		// An unknown value may still become the single approver, so only
		// report a combination that cannot become valid.
		unknown := da.ApproverTag.IsUnknown() || da.ApproverEmails.IsUnknown() || da.ApproverIsManager.IsUnknown()
		if len(set) > 1 || !unknown {
			got := "none"
			if len(set) > 0 {
				got = strings.Join(set, ", ")
			}
			diags.AddAttributeError(
				root,
				"Invalid designated approver",
				fmt.Sprintf("Exactly one of approver_tag, approver_emails, or approver_is_manager must be set, got: %s.", got),
			)
		}
		return
	}

	if manager {
		// The chat bot opens a group chat with the manager, who is the only
		// approver, so neither a channel nor a threshold applies.
		if isSetString(da.ChatChannel) {
			diags.AddAttributeError(root.AtName("chat_channel"), "Invalid designated approver",
				"chat_channel cannot be set when approver_is_manager is true.")
		}
		if !da.Threshold.IsNull() && !da.Threshold.IsUnknown() {
			diags.AddAttributeError(root.AtName("threshold"), "Invalid designated approver",
				"threshold cannot be set when approver_is_manager is true.")
		}
		return
	}

	if isSetString(da.ChatChannel) && notificationMethod.IsNull() {
		// The server validates the channel against the notification method and
		// has no rules for an unset one, so it rejects the pair outright.
		diags.AddAttributeError(root.AtName("chat_channel"), "Missing notification_method",
			"notification_method must be set when chat_channel is set.")
	}

	if da.Threshold.IsUnknown() {
		return
	}
	if da.Threshold.IsNull() {
		diags.AddAttributeError(root.AtName("threshold"), "Missing threshold",
			fmt.Sprintf("threshold must be set to 1 or more when %s is set.", set[0]))
		return
	}
	if emails := da.ApproverEmails; isSetList(emails) && !emails.IsUnknown() {
		if n := int64(len(emails.Elements())); da.Threshold.ValueInt64() > n {
			diags.AddAttributeError(root.AtName("threshold"), "Invalid threshold",
				fmt.Sprintf("threshold is %d but only %d approver_emails were given.", da.Threshold.ValueInt64(), n))
		}
	}
}

func validateSocialVotingBlock(sv *ApprovalWorkflowSocialVotingModel, diags *diag.Diagnostics) {
	if sv == nil {
		return
	}
	root := path.Root("social_voting")

	if sv.LocalThreshold.IsNull() {
		diags.AddAttributeError(root.AtName("local_threshold"), "Missing local_threshold",
			"local_threshold must be set to 1 or more when the social_voting block is present.")
	}
	if sv.TagThreshold.IsNull() {
		diags.AddAttributeError(root.AtName("tag_threshold"), "Missing tag_threshold",
			"tag_threshold must be set to 1 or more when the social_voting block is present.")
	}
	if sv.LocalThreshold.IsNull() || sv.TagThreshold.IsNull() ||
		sv.LocalThreshold.IsUnknown() || sv.TagThreshold.IsUnknown() {
		return
	}
	// The tag threshold is crossed after the local one, so a lower tag
	// threshold would never create the tag-wide rule.
	if sv.TagThreshold.ValueInt64() < sv.LocalThreshold.ValueInt64() {
		diags.AddAttributeError(root.AtName("tag_threshold"), "Invalid tag_threshold",
			fmt.Sprintf("tag_threshold (%d) must be greater than or equal to local_threshold (%d).",
				sv.TagThreshold.ValueInt64(), sv.LocalThreshold.ValueInt64()))
	}
}

func isSetString(v types.String) bool {
	return !v.IsNull() && (v.IsUnknown() || v.ValueString() != "")
}

func isSetList(v types.List) bool {
	return !v.IsNull() && (v.IsUnknown() || len(v.Elements()) > 0)
}

func (r *ApprovalWorkflowSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ApprovalWorkflowSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.upsert(ctx, &data, &resp.Diagnostics) {
		return
	}
	tflog.Info(ctx, "Created approval workflow settings", map[string]any{"tag": data.Tag.ValueString()})

	resp.Diagnostics.Append(resp.Identity.Set(ctx, ApprovalWorkflowSettingsIdentityModel{Tag: data.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ApprovalWorkflowSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ApprovalWorkflowSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tag := data.Tag.ValueString()
	settings, found, err := r.fetch(ctx, tag)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list approval workflow settings: %v", err))
		return
	}
	if !found {
		tflog.Info(ctx, "Approval workflow settings not found", map[string]any{"tag": tag})
		resp.State.RemoveResource(ctx)
		return
	}

	newData := approvalWorkflowProtoToModel(ctx, &data, settings, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, ApprovalWorkflowSettingsIdentityModel{Tag: newData.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &newData)...)
}

func (r *ApprovalWorkflowSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ApprovalWorkflowSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.upsert(ctx, &data, &resp.Diagnostics) {
		return
	}
	tflog.Info(ctx, "Updated approval workflow settings", map[string]any{"tag": data.Tag.ValueString()})

	resp.Diagnostics.Append(resp.Identity.Set(ctx, ApprovalWorkflowSettingsIdentityModel{Tag: data.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ApprovalWorkflowSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ApprovalWorkflowSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tag := data.Tag.ValueString()
	delReq := apipb.DeleteApprovalWorkflowSettingsRequest_builder{Tag: proto.String(tag)}.Build()
	if _, err := r.client.DeleteApprovalWorkflowSettings(ctx, delReq); err != nil && !isDeleteNoOp(err) {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete approval workflow settings for tag %q: %v", tag, err))
		return
	}
	tflog.Info(ctx, "Deleted approval workflow settings", map[string]any{"tag": tag})
}

func (r *ApprovalWorkflowSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Validate up front so an invalid tag fails here instead of at Read time,
	// when it is interpolated into the ListApprovalWorkflowSettings filter.
	if l := len(req.ID); l < 1 || l > tagNameMaxLen {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("tag %q must be between 1 and %d characters, got %d", req.ID, tagNameMaxLen, l),
		)
		return
	}
	if !tagNameRegex.MatchString(req.ID) {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("tag %q must contain only letters, digits, periods, colons, hyphens, and underscores", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("tag"), req.ID)...)
}

func (r *ApprovalWorkflowSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"tag": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

// upsert pushes the model to the server. UpdateApprovalWorkflowSettings
// replaces the tag's whole record, so Create and Update are the same call.
func (r *ApprovalWorkflowSettingsResource) upsert(ctx context.Context, data *ApprovalWorkflowSettingsResourceModel, diags *diag.Diagnostics) bool {
	settings := approvalWorkflowModelToProto(ctx, data, diags)
	if diags.HasError() {
		return false
	}

	upReq := apipb.UpdateApprovalWorkflowSettingsRequest_builder{
		Tag:                      proto.String(data.Tag.ValueString()),
		ApprovalWorkflowSettings: settings,
	}.Build()
	if _, err := r.client.UpdateApprovalWorkflowSettings(ctx, upReq); err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to update approval workflow settings for tag %q: %v", data.Tag.ValueString(), err))
		return false
	}
	return true
}

func (r *ApprovalWorkflowSettingsResource) fetch(ctx context.Context, tag string) (*apipb.ApprovalWorkflowSettings, bool, error) {
	ret, err := r.client.ListApprovalWorkflowSettings(ctx, apipb.ListApprovalWorkflowSettingsRequest_builder{
		Filter:   proto.String(fmt.Sprintf(`tag = "%s"`, tag)),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		return nil, false, err
	}
	for _, s := range ret.GetApprovalWorkflowSettings() {
		if s.GetTag() == tag {
			return s, true, nil
		}
	}
	return nil, false, nil
}

func approvalWorkflowModelToProto(ctx context.Context, data *ApprovalWorkflowSettingsResourceModel, diags *diag.Diagnostics) *apipb.ApprovalWorkflowSettings {
	b := apipb.ApprovalWorkflowSettings_builder{
		Tag:              data.Tag.ValueString(),
		ApprovalRuleType: apipb.RuleType(apipb.RuleType_value[data.ApprovalRuleType.ValueString()]),
		NotificationMethod: apipb.ApprovalWorkflowSettings_NotificationMethod(
			apipb.ApprovalWorkflowSettings_NotificationMethod_value[utils.NormalizeEnum(data.NotificationMethod.ValueString(), notificationMethodPrefix)]),
	}

	switch {
	case data.SelfService != nil:
		b.SelfService = apipb.SelfApprovalWorkflowSettings_builder{
			RequireJustification: data.SelfService.RequireJustification.ValueBool(),
		}.Build()
	case data.DesignatedApprover != nil:
		da := data.DesignatedApprover
		dab := apipb.DesignatedApproverWorkflowSettings_builder{
			ChatChannel:          da.ChatChannel.ValueString(),
			RequireJustification: da.RequireJustification.ValueBool(),
			AllowTagApproval:     da.AllowTagApproval.ValueBool(),
		}
		switch {
		case isSetString(da.ApproverTag):
			dab.Tag = apipb.DesignatedApproverTag_builder{
				Tag:       da.ApproverTag.ValueString(),
				Threshold: uint32(da.Threshold.ValueInt64()),
			}.Build()
		case isSetList(da.ApproverEmails):
			var emails []string
			diags.Append(da.ApproverEmails.ElementsAs(ctx, &emails, false)...)
			dab.Emails = apipb.DesignatedApproverEmails_builder{
				ApproverEmails: emails,
				Threshold:      uint32(da.Threshold.ValueInt64()),
			}.Build()
		default:
			dab.Manager = apipb.DesignatedApproverManager_builder{}.Build()
		}
		b.DesignatedApprover = dab.Build()
	case data.SocialVoting != nil:
		sv := data.SocialVoting
		var tags []string
		if !sv.TagsToConsiderVotesFrom.IsNull() && !sv.TagsToConsiderVotesFrom.IsUnknown() {
			diags.Append(sv.TagsToConsiderVotesFrom.ElementsAs(ctx, &tags, false)...)
		}
		b.SocialVoting = apipb.SocialVotingWorkflowSettings_builder{
			LocalThreshold:          uint32(sv.LocalThreshold.ValueInt64()),
			TagThreshold:            uint32(sv.TagThreshold.ValueInt64()),
			TagsToConsiderVotesFrom: tags,
			RequireJustification:    sv.RequireJustification.ValueBool(),
		}.Build()
	default:
		// No workflow block: the tag has no approval workflow, and a
		// lower-precedence tag's workflow no longer reaches its users.
		b.None = apipb.NoneApprovalWorkflowSettings_builder{}.Build()
	}

	return b.Build()
}

// approvalWorkflowProtoToModel renders the server's record as a model. prior
// is the state being refreshed; it supplies the enum spelling and the
// server-defaulted vote tags, so a refresh never manufactures a diff over a
// value the configuration never set.
func approvalWorkflowProtoToModel(ctx context.Context, prior *ApprovalWorkflowSettingsResourceModel, s *apipb.ApprovalWorkflowSettings, diags *diag.Diagnostics) ApprovalWorkflowSettingsResourceModel {
	out := ApprovalWorkflowSettingsResourceModel{
		Tag:                types.StringValue(s.GetTag()),
		ApprovalRuleType:   types.StringValue(s.GetApprovalRuleType().String()),
		NotificationMethod: types.StringNull(),
	}
	if s.GetNotificationMethod() != apipb.ApprovalWorkflowSettings_NOTIFICATION_METHOD_UNSPECIFIED {
		out.NotificationMethod = types.StringValue(utils.MatchEnumForm(
			prior.NotificationMethod.ValueString(), s.GetNotificationMethod().String(), notificationMethodPrefix))
	}

	switch s.WhichWorkflow() {
	case apipb.ApprovalWorkflowSettings_SelfService_case:
		priorSS := prior.SelfService
		if priorSS == nil {
			priorSS = &ApprovalWorkflowSelfServiceModel{}
		}
		out.SelfService = &ApprovalWorkflowSelfServiceModel{
			RequireJustification: boolOrNull(priorSS.RequireJustification, s.GetSelfService().GetRequireJustification()),
		}
	case apipb.ApprovalWorkflowSettings_DesignatedApprover_case:
		da := s.GetDesignatedApprover()
		priorDA := prior.DesignatedApprover
		if priorDA == nil {
			priorDA = &ApprovalWorkflowDesignatedApproverModel{}
		}
		m := &ApprovalWorkflowDesignatedApproverModel{
			ApproverTag:          types.StringNull(),
			ApproverEmails:       types.ListNull(types.StringType),
			ApproverIsManager:    types.BoolNull(),
			Threshold:            types.Int64Null(),
			ChatChannel:          stringOrNull(da.GetChatChannel()),
			RequireJustification: boolOrNull(priorDA.RequireJustification, da.GetRequireJustification()),
			AllowTagApproval:     boolOrNull(priorDA.AllowTagApproval, da.GetAllowTagApproval()),
		}
		switch da.WhichApprover() {
		case apipb.DesignatedApproverWorkflowSettings_Tag_case:
			m.ApproverTag = types.StringValue(da.GetTag().GetTag())
			m.Threshold = types.Int64Value(int64(da.GetTag().GetThreshold()))
		case apipb.DesignatedApproverWorkflowSettings_Emails_case:
			list, d := types.ListValueFrom(ctx, types.StringType, da.GetEmails().GetApproverEmails())
			diags.Append(d...)
			m.ApproverEmails = list
			m.Threshold = types.Int64Value(int64(da.GetEmails().GetThreshold()))
		case apipb.DesignatedApproverWorkflowSettings_Manager_case:
			m.ApproverIsManager = types.BoolValue(true)
		}
		out.DesignatedApprover = m
	case apipb.ApprovalWorkflowSettings_SocialVoting_case:
		sv := s.GetSocialVoting()
		priorSV := prior.SocialVoting
		if priorSV == nil {
			priorSV = &ApprovalWorkflowSocialVotingModel{TagsToConsiderVotesFrom: types.ListNull(types.StringType)}
		}
		out.SocialVoting = &ApprovalWorkflowSocialVotingModel{
			LocalThreshold:          types.Int64Value(int64(sv.GetLocalThreshold())),
			TagThreshold:            types.Int64Value(int64(sv.GetTagThreshold())),
			TagsToConsiderVotesFrom: voteTagsToTF(ctx, sv.GetTagsToConsiderVotesFrom(), s.GetTag(), priorSV.TagsToConsiderVotesFrom, diags),
			RequireJustification:    boolOrNull(priorSV.RequireJustification, sv.GetRequireJustification()),
		}
	}

	return out
}

// voteTagsToTF keeps tags_to_consider_votes_from as the configuration wrote it
// whenever the configuration named no tags at all. The server replaces an
// unset or empty list with the workflow's own tag, so reading that default
// back would diff against the configuration on every plan.
func voteTagsToTF(ctx context.Context, tags []string, workflowTag string, prior types.List, diags *diag.Diagnostics) types.List {
	namedNone := prior.IsNull() || len(prior.Elements()) == 0
	if len(tags) == 0 || (namedNone && len(tags) == 1 && tags[0] == workflowTag) {
		if prior.IsNull() {
			return types.ListNull(types.StringType)
		}
		// An explicitly empty list, which is already correctly typed.
		return prior
	}
	list, d := types.ListValueFrom(ctx, types.StringType, tags)
	diags.Append(d...)
	return list
}

func stringOrNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// boolOrNull keeps an optional boolean null when the configuration never set
// it and the server reports the proto zero value. These fields have no
// presence on the wire, so reading false back verbatim would diff against a
// configuration that omitted the attribute, on every plan.
func boolOrNull(prior types.Bool, v bool) types.Bool {
	if !v && prior.IsNull() {
		return types.BoolNull()
	}
	return types.BoolValue(v)
}
