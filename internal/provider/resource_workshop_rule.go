// Copyright 2024 North Pole Security, Inc.

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
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"
	"google.golang.org/protobuf/proto"

	syncpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &RuleResource{}
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
	Identifier types.String `tfsdk:"identifier"`
	RuleType   types.String `tfsdk:"rule_type"`
	Policy     types.String `tfsdk:"policy"`
	Tag        types.String `tfsdk:"tag"`
	Comment    types.String `tfsdk:"comment"`
	CustomMsg  types.String `tfsdk:"custom_msg"`
	CustomURL  types.String `tfsdk:"custom_url"`
	CELExpr    types.String `tfsdk:"cel_expr"`

	Id types.String `tfsdk:"id"`
}

func (r *RuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_rule"
}

func (r *RuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Rule",

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
			"tag": schema.StringAttribute{
				MarkdownDescription: "The tag for this rule",
				Required:            true,
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
			"cel_expr": schema.StringAttribute{
				MarkdownDescription: "A CEL expression to evaluate",
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

	if err := createRule(ctx, r.client, &data); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create rule: %v", err))
		return
	}

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

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data RuleResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteRule(ctx, apipb.DeleteRuleRequest_builder{
		RuleId: proto.String(data.Id.ValueString()),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete existing rule: %v", err))
		return
	}

	if err := createRule(ctx, r.client, &data); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create rule: %v", err))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RuleResourceModel

	// Read Terraform prior state data into the model
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
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func createRule(ctx context.Context, client svcpb.WorkshopServiceClient, data *RuleResourceModel) error {
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

	crResp, err := client.CreateRule(ctx, apipb.CreateRuleRequest_builder{
		Rule: rule,
	}.Build())
	if err == nil {
		data.Id = types.StringValue(crResp.GetRuleId())
		tflog.Info(ctx, fmt.Sprintf("Created rule: %q", data.Id))
	}
	return err
}
