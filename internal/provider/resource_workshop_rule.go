// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"
	"google.golang.org/protobuf/proto"

	syncpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &RuleResource{}
var _ resource.ResourceWithConfigure = &RuleResource{}
var _ resource.ResourceWithImportState = &RuleResource{}

func NewRuleResource() resource.Resource {
	return &RuleResource{}
}

// RuleResource defines the resource implementation.
type RuleResource struct {
	client svcpb.WorkshopServiceClient
}

// RuleResourceModel describes the resource data model.
type RuleResourceModel struct {
	Identifier  types.String `tfsdk:"identifier"`
	RuleType    types.String `tfsdk:"rule_type"`
	Policy      types.String `tfsdk:"policy"`
	BlockReason types.String `tfsdk:"block_reason"`
	Tag         types.String `tfsdk:"tag"`
	Comment     types.String `tfsdk:"comment"`
	CustomMsg   types.String `tfsdk:"custom_msg"`
	CustomURL   types.String `tfsdk:"custom_url"`
	CELExpr     types.String `tfsdk:"cel_expr"`

	Id types.String `tfsdk:"id"`
}

func (r *RuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_rule"
}

func (r *RuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The `nps_workshop_rule` resource manages Rules.",

		Attributes: map[string]schema.Attribute{
			"identifier": schema.StringAttribute{
				MarkdownDescription: "The identifier for this rule",
				Required:            true,
			},
			"rule_type": schema.StringAttribute{
				MarkdownDescription: "The type of this rule",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(syncpb.RuleType(0).Descriptor())...),
				},
			},
			"policy": schema.StringAttribute{
				MarkdownDescription: "The policy for this rule",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(syncpb.Policy(0).Descriptor())...),
				},
			},
			"block_reason": schema.StringAttribute{
				MarkdownDescription: "The block reason for this rule",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(apipb.Rule_BlockReason(0).Descriptor())...),
				},
			},
			"tag": schema.StringAttribute{
				MarkdownDescription: "The tag for this rule",
				Required:            true,
			},
			"cel_expr": schema.StringAttribute{
				MarkdownDescription: "A CEL expression to evaluate",
				Optional:            true,
			},
			"comment": schema.StringAttribute{
				MarkdownDescription: "A comment to add to this rule",
				Optional:            true,
			},
			"custom_msg": schema.StringAttribute{
				MarkdownDescription: "A custom message to display to the user",
				Optional:            true,
			},
			"custom_url": schema.StringAttribute{
				MarkdownDescription: "A custom URL to redirect the user to",
				Optional:            true,
			},

			// Computed value, returned from Create
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of this rule",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
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

	ruleType := syncpb.RuleType_value[data.RuleType.ValueString()]
	rulePolicy := syncpb.Policy_value[data.Policy.ValueString()]

	rule := apipb.Rule_builder{
		Identifier: data.Identifier.ValueString(),
		RuleType:   syncpb.RuleType(ruleType),
		Policy:     syncpb.Policy(rulePolicy),
		Tag:        data.Tag.ValueString(),
		Comment:    data.Comment.ValueString(),
		CustomMsg:  data.CustomMsg.ValueString(),
		CustomUrl:  data.CustomURL.ValueString(),
		CelExpr:    data.CELExpr.ValueString(),
	}.Build()

	crResp, err := r.client.CreateRule(ctx, apipb.CreateRuleRequest_builder{
		Rule: rule,
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create rule: %v", err))
		return
	}

	data.Id = types.StringValue(crResp.GetRuleId())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
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
	filter := fmt.Sprintf(`rule_id = "%s" OR (identifier = "%s" AND rule_type = "%s" AND tag = "%s")`,
		data.Id.ValueString(), data.Identifier.ValueString(), data.RuleType.ValueString(), data.Tag.ValueString())

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

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Because an "upsert" of a rule results in a new rule ID, it's not possible
	// for us to implement in-place updates.
	resp.Diagnostics.AddError("Client Error", "nps_workshop_rule does not support in-place updates")
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
