// Copyright 2024 North Pole Security, Inc.

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

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
	HostID     types.String `tfsdk:"host_id"`

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
			},
			"policy": schema.StringAttribute{
				MarkdownDescription: "The policy for this rule",
				Required:            true,
			},
			"host_id": schema.StringAttribute{
				MarkdownDescription: "The host ID to apply to this rule. If unspecified the rule will be global",
				Optional:            true,
			},

			// Computed value, returned from Create
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of this rule",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
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

	crResp, err := r.client.CreateRule(ctx, &apipb.CreateRuleRequest{
		Rule: &apipb.Rule{
			Identifier: data.Identifier.ValueString(),
			RuleType:   syncpb.RuleType(ruleType),
			Policy:     syncpb.Policy(rulePolicy),
			HostId:     data.HostID.ValueString(),
		},
	})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create rule: %v", err))
		return
	}
	if crResp.GetRuleId() == "" {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get rule ID for new rule"))
		return
	}

	data.Id = types.StringValue(crResp.GetRuleId())
	tflog.Info(ctx, fmt.Sprintf("Created rule: %q", data.Id))

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

	// If applicable, this is a great opportunity to initialize any necessary
	// provider client data and make a call using it.
	// httpResp, err := r.client.Do(httpReq)
	// if err != nil {
	//     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read example, got error: %s", err))
	//     return
	// }

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

	_, err := r.client.DeleteRule(ctx, &apipb.DeleteRuleRequest{
		RuleId: data.Identifier.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete existing rule: %v", err))
		return
	}

	ruleType := syncpb.RuleType_value[data.RuleType.ValueString()]
	rulePolicy := syncpb.Policy_value[data.Policy.ValueString()]

	crResp, err := r.client.CreateRule(ctx, &apipb.CreateRuleRequest{
		Rule: &apipb.Rule{
			Identifier: data.Identifier.ValueString(),
			RuleType:   syncpb.RuleType(ruleType),
			Policy:     syncpb.Policy(rulePolicy),
			HostId:     data.HostID.ValueString(),
		},
	})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create rule: %v", err))
		return
	}
	if crResp.GetRuleId() == "" {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get rule ID for new rule"))
		return
	}

	data.Id = types.StringValue(crResp.GetRuleId())
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RuleResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteRule(ctx, &apipb.DeleteRuleRequest{
		RuleId: data.Id.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete rule: %v", err))
		return
	}
}

func (r *RuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
