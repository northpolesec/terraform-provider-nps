// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"
	"google.golang.org/protobuf/proto"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &RuleResource{}
var _ resource.ResourceWithConfigure = &RuleResource{}
var _ resource.ResourceWithImportState = &RuleResource{}
var _ resource.ResourceWithIdentity = &RuleResource{}
var _ list.ListResource = &RuleResource{}
var _ list.ListResourceWithConfigure = &RuleResource{}

func NewRuleResource() resource.Resource {
	return &RuleResource{}
}

// RuleResource defines the resource implementation.
type RuleResource struct {
	client svcpb.WorkshopServiceClient
}

// RuleIdentityModel describes the identity data model.
type RuleIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

// RuleResourceModel describes the resource data model.
type RuleResourceModel struct {
	Identifier            types.String                    `tfsdk:"identifier"`
	RuleType              types.String                    `tfsdk:"rule_type"`
	Policy                types.String                    `tfsdk:"policy"`
	BlockReason           types.String                    `tfsdk:"block_reason"`
	Tag                   types.String                    `tfsdk:"tag"`
	Comment               types.String                    `tfsdk:"comment"`
	CustomMsg             types.String                    `tfsdk:"custom_msg"`
	CustomURL             types.String                    `tfsdk:"custom_url"`
	CELExpr               types.String                    `tfsdk:"cel_expr"`
	AffectedHostThreshold *RuleAffectedHostThresholdModel `tfsdk:"affected_host_threshold"`

	Id types.String `tfsdk:"id"`
}

// RuleAffectedHostThresholdModel describes the affected_host_threshold block.
type RuleAffectedHostThresholdModel struct {
	HostCount types.Int32 `tfsdk:"host_count"`
	Days      types.Int32 `tfsdk:"days"`
}

// blockReasonDefault resolves an unset block_reason the same way the server
// does: blocklist-family policies default to BLOCK_REASON_POLICY, while other
// policies (which the server forbids a block reason on) resolve to null. This
// keeps an unset block_reason from showing a perpetual diff without copying the
// value back from server state.
type blockReasonDefault struct{}

func (m blockReasonDefault) Description(context.Context) string {
	return "Defaults block_reason to BLOCK_REASON_POLICY for blocklist policies when unset."
}

func (m blockReasonDefault) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m blockReasonDefault) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Respect an explicitly configured value.
	if !req.ConfigValue.IsNull() {
		return
	}

	var policy types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("policy"), &policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.PlanValue = resolveBlockReason(policy.ValueString())
}

// resolveBlockReason returns the block_reason for an unset config value given
// the rule's policy: blocklist-family policies default to BLOCK_REASON_POLICY
// (matching the server), everything else resolves to null.
func resolveBlockReason(policy string) types.String {
	if strings.Contains(policy, "BLOCKLIST") {
		return types.StringValue("BLOCK_REASON_POLICY")
	}
	return types.StringNull()
}

func (r *RuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_rule"
	// The rule ID (used as the identity) changes on every upsert, including
	// in-place updates, so the identity is mutable across the resource's life.
	resp.ResourceBehavior.MutableIdentity = true
}

func (r *RuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_rule resource manages Rules. Management of rules requires the read:rules and write:rules permissions. Changing identifier, rule_type, or tag forces replacement; add a create_before_destroy lifecycle block to avoid a window where the rule does not exist.",
		MarkdownDescription: "The `nps_workshop_rule` resource manages Rules.\n\nManagement of rules requires the `read:rules` and `write:rules` permissions.\n\nUpdates to non-key fields (such as `policy` or `comment`) are applied atomically in place. Changing the rule's natural key (`identifier`, `rule_type`, or `tag`) forces the rule to be replaced: by default Terraform destroys the old rule before creating the new one, leaving a brief window with no rule in place. To avoid that window, add a `create_before_destroy` lifecycle block:\n\n```hcl\nresource \"nps_workshop_rule\" \"example\" {\n  # ...\n  lifecycle {\n    create_before_destroy = true\n  }\n}\n```",

		Attributes: map[string]schema.Attribute{
			"identifier": schema.StringAttribute{
				Description:         "The identifier for this rule. The format of this identifier depends on the rule type.",
				MarkdownDescription: "The identifier for this rule. The format of this identifier depends on the rule type.",
				Required:            true,
				// Part of the natural key (identifier, rule_type, tag). The upsert
				// only supersedes the old rule when the key matches, so changing the
				// key must replace rather than update in place.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"rule_type": schema.StringAttribute{
				Description:         "The type of this rule. The possible values are: BINARY, CERTIFICATE, TEAMID, SIGNINGID, and CDHASH.",
				MarkdownDescription: "The type of this rule. The possible values are: `BINARY`, `CERTIFICATE`, `TEAMID`, `SIGNINGID`, and `CDHASH`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(apipb.RuleType(0).Descriptor())...),
				},
				// Part of the natural key; see identifier.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"policy": schema.StringAttribute{
				Description:         "The policy for this rule. The possible values are: ALLOWLIST, ALLOWLIST_COMPILER, BLOCKLIST, SILENT_BLOCKLIST, and CEL.",
				MarkdownDescription: "The policy for this rule. The possible values are: `ALLOWLIST`, `ALLOWLIST_COMPILER`, `BLOCKLIST`, `SILENT_BLOCKLIST`, and `CEL`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(apipb.Policy(0).Descriptor())...),
				},
			},
			"block_reason": schema.StringAttribute{
				Description:         "The block reason for this rule. The possible values are: BLOCK_REASON_POLICY and BLOCK_REASON_MALICIOUS.",
				MarkdownDescription: "The block reason for this rule. The possible values are: `BLOCK_REASON_POLICY`, and `BLOCK_REASON_MALICIOUS`.",
				Optional:            true,
				// Computed + blockReasonDefault: for blocklist policies the server
				// treats an unset block_reason as BLOCK_REASON_POLICY. We resolve
				// that default ourselves at plan time so an unset value does not
				// produce a perpetual diff against the server-assigned POLICY.
				Computed: true,
				Validators: []validator.String{
					// Only the meaningful block reasons; BLOCK_REASON_UNSPECIFIED is
					// reserved for the unset/default case handled by blockReasonDefault.
					stringvalidator.OneOf("BLOCK_REASON_POLICY", "BLOCK_REASON_MALICIOUS"),
				},
				PlanModifiers: []planmodifier.String{
					blockReasonDefault{},
				},
			},
			"tag": schema.StringAttribute{
				Description:         "The tag for this rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				MarkdownDescription: "The tag for this rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				Required:            true,
				// Part of the natural key; see identifier.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"cel_expr": schema.StringAttribute{
				Description:         "A CEL expression to evaluate when this rule matches. Only valid when the policy is set to CEL.",
				MarkdownDescription: "A CEL expression to evaluate when this rule matches. Only valid when the policy is set to `CEL`.",
				Optional:            true,
			},
			"comment": schema.StringAttribute{
				MarkdownDescription: "A comment to add to this rule. Will be displayed in the Workshop UI.",
				Optional:            true,
			},
			"custom_msg": schema.StringAttribute{
				MarkdownDescription: "A custom message to display to the user when this rule causes Santa to block the execution.",
				Optional:            true,
			},
			"custom_url": schema.StringAttribute{
				Description:         "A custom URL to redirect the user to when this rule causes Santa to block the execution. Setting a custom URL will override the EventDetailURL used by the Open button.",
				MarkdownDescription: "A custom URL to redirect the user to when this rule causes Santa to block the execution. Setting a custom URL will override the `EventDetailURL` used by the Open button.",
				Optional:            true,
			},

			// Computed value, returned from Create. The ID changes on every
			// upsert (including in-place updates), so it is intentionally left
			// without UseStateForUnknown: it plans as "known after apply"
			// whenever the rule changes.
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The automatically generated ID of this rule",
			},
		},

		Blocks: map[string]schema.Block{
			"affected_host_threshold": schema.SingleNestedBlock{
				Description:         "If set, the server will count how many hosts (matching the rule's tag) have run a binary covered by this rule's identifier and rule_type within the lookback window. If the count is greater than or equal to host_count, the rule is not created and a FailedPrecondition error is returned. The check applies the same identifier match used for resolution; for CEL/SEATBELT rules the count reflects the underlying identifier and may overstate the true impact. Note: this block is only supported in Workshop 2025.5 and later; in earlier versions it will be ignored by the server.",
				MarkdownDescription: "If set, the server will count how many hosts (matching the rule's tag) have run a binary covered by this rule's `identifier` and `rule_type` within the lookback window. If the count is greater than or equal to `host_count`, the rule is not created and a `FailedPrecondition` error is returned. The check applies the same identifier match used for resolution; for `CEL`/`SEATBELT` rules the count reflects the underlying identifier and may overstate the true impact. **Note:** this block is only supported in Workshop 2025.5 and later; in earlier versions it will be ignored by the server.",
				Attributes: map[string]schema.Attribute{
					"host_count": schema.Int32Attribute{
						Description:         "The rule is rejected when at least this many hosts have run a covered binary within the lookback window. Must be greater than 0. Required when affected_host_threshold is set.",
						MarkdownDescription: "The rule is rejected when at least this many hosts have run a covered binary within the lookback window. Must be greater than `0`. Required when `affected_host_threshold` is set.",
						Optional:            true,
						Validators: []validator.Int32{
							int32validator.AtLeast(1),
						},
					},
					"days": schema.Int32Attribute{
						Description:         "Lookback window in days for counting hosts. Must be in [1, 90]. Required when affected_host_threshold is set.",
						MarkdownDescription: "Lookback window in days for counting hosts. Must be in `[1, 90]`. Required when `affected_host_threshold` is set.",
						Optional:            true,
						Validators: []validator.Int32{
							int32validator.Between(1, 90),
						},
					},
				},
			},
		},
	}
}

func (r *RuleResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		utils.ConfigValidatorFunc("Validate CEL rules have an expression", func(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
			var data RuleResourceModel
			resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

			if data.BlockReason.ValueString() != "" && data.Policy.ValueString() != "BLOCKLIST" && data.Policy.ValueString() != "SILENT_BLOCKLIST" {
				resp.Diagnostics.AddError("Block reason is only valid for BLOCKLIST rules", "")
			}

			if data.Policy.ValueString() == "CEL" && data.CELExpr.ValueString() == "" {
				resp.Diagnostics.AddError("CEL expression is required", "CEL expression is required when policy is set to CEL")
			}

			if data.AffectedHostThreshold != nil {
				if data.AffectedHostThreshold.HostCount.IsNull() {
					resp.Diagnostics.AddAttributeError(
						path.Root("affected_host_threshold").AtName("host_count"),
						"host_count is required",
						"host_count is required when affected_host_threshold is set",
					)
				}
				if data.AffectedHostThreshold.Days.IsNull() {
					resp.Diagnostics.AddAttributeError(
						path.Root("affected_host_threshold").AtName("days"),
						"days is required",
						"days is required when affected_host_threshold is set",
					)
				}
			}
		}),
	}
}

func (r *RuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
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

func (r *RuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RuleResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	crResp, err := r.client.CreateRule(ctx, buildCreateRuleRequest(data))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create rule: %v", err))
		return
	}

	data.Id = types.StringValue(crResp.GetRuleId())

	// Set the identity
	resp.Diagnostics.Append(resp.Identity.Set(ctx, RuleIdentityModel{Id: data.Id})...)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// buildCreateRuleRequest builds the (upsert) CreateRuleRequest from the model.
func buildCreateRuleRequest(data RuleResourceModel) *apipb.CreateRuleRequest {
	ruleType := apipb.RuleType_value[data.RuleType.ValueString()]
	rulePolicy := apipb.Policy_value[data.Policy.ValueString()]

	ruleBuilder := apipb.Rule_builder{
		Identifier: data.Identifier.ValueString(),
		RuleType:   apipb.RuleType(ruleType),
		Policy:     apipb.Policy(rulePolicy),
		Tag:        data.Tag.ValueString(),
		Comment:    data.Comment.ValueString(),
		CustomMsg:  data.CustomMsg.ValueString(),
		CustomUrl:  data.CustomURL.ValueString(),
		CelExpr:    data.CELExpr.ValueString(),
	}
	if br := data.BlockReason.ValueString(); br != "" {
		ruleBuilder.BlockReason = apipb.Rule_BlockReason(apipb.Rule_BlockReason_value[br])
	}

	createReq := apipb.CreateRuleRequest_builder{
		Rule: ruleBuilder.Build(),
	}
	if data.AffectedHostThreshold != nil {
		threshold := apipb.CreateRuleRequest_AffectedHostThreshold_builder{}
		if !data.AffectedHostThreshold.HostCount.IsNull() && !data.AffectedHostThreshold.HostCount.IsUnknown() {
			threshold.HostCount = proto.Int32(data.AffectedHostThreshold.HostCount.ValueInt32())
		}
		if !data.AffectedHostThreshold.Days.IsNull() && !data.AffectedHostThreshold.Days.IsUnknown() {
			threshold.Days = proto.Int32(data.AffectedHostThreshold.Days.ValueInt32())
		}
		createReq.AffectedHostThreshold = threshold.Build()
	}
	return createReq.Build()
}

func (r *RuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RuleResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Most of the time we want to find a rule by its ID, which works for importing
	// and seeing that a rule still exists. However, if a rule has been "updated" the
	// rule ID will change, so we need to query by the triplet of identifier, rule_type,
	// and tag instead. This lets Terraform show a diff instead of appearing to create
	// the rule from scratch.
	filter := ruleReadFilter(data)

	ret, err := r.client.ListRules(ctx, apipb.ListRulesRequest_builder{
		Filter:   proto.String(filter),
		PageSize: proto.Int32(1),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list rules: %v", err))
		return
	}
	if len(ret.GetRules()) == 0 {
		// The rule was not found, remove it from the state so Terraform will offer
		// to create it.
		resp.State.RemoveResource(ctx)
		return
	}

	// Now that we've found the rule, overwrite the state data with the actual
	// values retrieved via the API.
	rule := ret.GetRules()[0]
	data.Id = types.StringValue(rule.GetRuleId())
	data.Identifier = types.StringValue(rule.GetIdentifier())
	data.RuleType = types.StringValue(rule.GetRuleType().String())
	data.Policy = types.StringValue(rule.GetPolicy().String())
	data.Tag = types.StringValue(rule.GetTag())

	if rule.GetBlockReason() != apipb.Rule_BLOCK_REASON_UNSPECIFIED {
		data.BlockReason = types.StringValue(rule.GetBlockReason().String())
	}
	if rule.GetComment() != "" {
		data.Comment = types.StringValue(rule.GetComment())
	}
	if rule.GetCustomMsg() != "" {
		data.CustomMsg = types.StringValue(rule.GetCustomMsg())
	}
	if rule.GetCustomUrl() != "" {
		data.CustomURL = types.StringValue(rule.GetCustomUrl())
	}
	if rule.GetCelExpr() != "" {
		data.CELExpr = types.StringValue(rule.GetCelExpr())
	}

	// Set the identity
	resp.Diagnostics.Append(resp.Identity.Set(ctx, RuleIdentityModel{Id: data.Id})...)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan RuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newID, diags := r.upsertRule(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if newID.IsNull() {
		return
	}
	plan.Id = newID

	resp.Diagnostics.Append(resp.Identity.Set(ctx, RuleIdentityModel{Id: plan.Id})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// upsertRule performs an atomic update via the CreateRule upsert RPC and
// returns the new rule ID. CreateRule is an upsert: the server supersedes the
// existing rule sharing this rule's (tag, rule_type, identifier) key and
// returns a new ID, so the update is atomic and a failure leaves the old rule
// in place. The key attributes are RequiresReplace, so Update only ever changes
// non-key fields where the server is guaranteed to supersede; we never delete
// the old rule ourselves. Returns a null ID (with diagnostics) on failure.
func (r *RuleResource) upsertRule(ctx context.Context, plan RuleResourceModel) (types.String, diag.Diagnostics) {
	var diags diag.Diagnostics

	crResp, err := r.client.CreateRule(ctx, buildCreateRuleRequest(plan))
	if err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to update rule: %v", err))
		return types.StringNull(), diags
	}
	return types.StringValue(crResp.GetRuleId()), diags
}

func (r *RuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RuleResourceModel

	// Read Terraform prior state data into the model, which will give us the
	// rule ID to delete with.
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteRule(ctx, apipb.DeleteRuleRequest_builder{
		RuleId: proto.String(data.Id.ValueString()),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete rule: %v", err))
		return
	}
}

func (r *RuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import a rule by ID, which will trigger a Read.
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *RuleResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func NewRuleListResource() list.ListResource {
	return &RuleResource{}
}

func (r *RuleResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "List all rules in the Workshop instance.",
		Attributes:  map[string]listschema.Attribute{},
	}
}

func (r *RuleResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	stream.Results = func(push func(list.ListResult) bool) {
		ret, err := r.client.ListRules(ctx, apipb.ListRulesRequest_builder{}.Build())
		if err != nil {
			result := req.NewListResult(ctx)
			result.Diagnostics.AddError("Client Error", "Failed to list rules: "+err.Error())
			push(result)
			return
		}

		for _, rule := range ret.GetRules() {
			result := req.NewListResult(ctx)
			result.DisplayName = fmt.Sprintf("%s %s", rule.GetRuleType().String(), rule.GetIdentifier())

			result.Diagnostics.Append(result.Identity.Set(ctx, RuleIdentityModel{
				Id: types.StringValue(rule.GetRuleId()),
			})...)

			if req.IncludeResource {
				model := RuleResourceModel{
					Id:         types.StringValue(rule.GetRuleId()),
					Identifier: types.StringValue(rule.GetIdentifier()),
					RuleType:   types.StringValue(rule.GetRuleType().String()),
					Policy:     types.StringValue(rule.GetPolicy().String()),
					Tag:        types.StringValue(rule.GetTag()),
				}

				if rule.GetBlockReason() != apipb.Rule_BLOCK_REASON_UNSPECIFIED {
					model.BlockReason = types.StringValue(rule.GetBlockReason().String())
				}
				if rule.GetComment() != "" {
					model.Comment = types.StringValue(rule.GetComment())
				}
				if rule.GetCustomMsg() != "" {
					model.CustomMsg = types.StringValue(rule.GetCustomMsg())
				}
				if rule.GetCustomUrl() != "" {
					model.CustomURL = types.StringValue(rule.GetCustomUrl())
				}
				if rule.GetCelExpr() != "" {
					model.CELExpr = types.StringValue(rule.GetCelExpr())
				}

				result.Diagnostics.Append(result.Resource.Set(ctx, model)...)
			}

			if !push(result) {
				return
			}
		}
	}
}

// ruleReadFilter builds the filter string for the ListRules API call in Read.
// During import, only the ID is set, so we must avoid sending empty enum values
// (like rule_type) which the server would reject.
func ruleReadFilter(data RuleResourceModel) string {
	filter := fmt.Sprintf(`rule_id = "%s"`, data.Id.ValueString())
	if !data.RuleType.IsNull() && !data.RuleType.IsUnknown() && data.RuleType.ValueString() != "" {
		filter += fmt.Sprintf(` OR (identifier = "%s" AND rule_type = "%s" AND tag = "%s")`,
			data.Identifier.ValueString(), data.RuleType.ValueString(), data.Tag.ValueString())
	}
	return filter
}
