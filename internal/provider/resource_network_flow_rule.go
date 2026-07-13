// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
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
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"
	"google.golang.org/protobuf/proto"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &NetworkFlowRuleResource{}
var _ resource.ResourceWithConfigure = &NetworkFlowRuleResource{}
var _ resource.ResourceWithImportState = &NetworkFlowRuleResource{}
var _ resource.ResourceWithIdentity = &NetworkFlowRuleResource{}
var _ resource.ResourceWithConfigValidators = &NetworkFlowRuleResource{}
var _ list.ListResource = &NetworkFlowRuleResource{}
var _ list.ListResourceWithConfigure = &NetworkFlowRuleResource{}

func NewNetworkFlowRuleResource() resource.Resource {
	return &NetworkFlowRuleResource{}
}

// NetworkFlowRuleResource defines the resource implementation.
type NetworkFlowRuleResource struct {
	client svcpb.WorkshopServiceClient
}

// NetworkFlowRuleIdentityModel describes the identity data model.
type NetworkFlowRuleIdentityModel struct {
	Id types.Int64 `tfsdk:"id"`
}

// NetworkFlowRuleResourceModel describes the resource data model.
type NetworkFlowRuleResourceModel struct {
	Tag       types.String `tfsdk:"tag"`
	Name      types.String `tfsdk:"name"`
	Action    types.String `tfsdk:"action"`
	Direction types.String `tfsdk:"direction"`

	// precedence_hint oneof. At most one may be set.
	Priority types.Bool  `tfsdk:"priority"`
	Rank     types.Int64 `tfsdk:"rank"`

	ProcessCdHashes   types.List `tfsdk:"process_cd_hashes"`
	ProcessSigningIds types.List `tfsdk:"process_signing_ids"`
	ProcessTeamIds    types.List `tfsdk:"process_team_ids"`

	RemoteHostnames types.List `tfsdk:"remote_hostnames"`
	RemoteDomains   types.List `tfsdk:"remote_domains"`
	RemoteAddresses types.List `tfsdk:"remote_addresses"`

	Protocols types.List `tfsdk:"protocols"`

	CustomMsg types.String `tfsdk:"custom_msg"`
	CustomUrl types.String `tfsdk:"custom_url"`
	Comment   types.String `tfsdk:"comment"`

	Ports []NetworkFlowRulePortRangeModel `tfsdk:"ports"`

	Id types.Int64 `tfsdk:"id"`
}

func clearNetworkFlowRuleOptionalState(data *NetworkFlowRuleResourceModel) {
	data.ProcessCdHashes = normalizeAbsentOptionalList(data.ProcessCdHashes, types.StringType)
	data.ProcessSigningIds = normalizeAbsentOptionalList(data.ProcessSigningIds, types.StringType)
	data.ProcessTeamIds = normalizeAbsentOptionalList(data.ProcessTeamIds, types.StringType)
	data.RemoteHostnames = normalizeAbsentOptionalList(data.RemoteHostnames, types.StringType)
	data.RemoteDomains = normalizeAbsentOptionalList(data.RemoteDomains, types.StringType)
	data.RemoteAddresses = normalizeAbsentOptionalList(data.RemoteAddresses, types.StringType)
	data.Protocols = normalizeAbsentOptionalList(data.Protocols, types.Int64Type)
	data.CustomMsg = normalizeAbsentOptionalString(data.CustomMsg)
	data.CustomUrl = normalizeAbsentOptionalString(data.CustomUrl)
	data.Comment = normalizeAbsentOptionalString(data.Comment)
	data.Ports = normalizeAbsentOptionalSlice(data.Ports)
}

func networkFlowRulePortsFromProto(prior []NetworkFlowRulePortRangeModel, ports []*apipb.NetworkFlowRule_PortRange) []NetworkFlowRulePortRangeModel {
	if len(ports) == 0 {
		return normalizeAbsentOptionalSlice(prior)
	}

	result := make([]NetworkFlowRulePortRangeModel, 0, len(ports))
	for i, port := range ports {
		model := NetworkFlowRulePortRangeModel{
			Low:  types.Int64Value(int64(port.GetLow())),
			High: types.Int64Null(),
		}
		if port.GetHigh() != 0 {
			model.High = types.Int64Value(int64(port.GetHigh()))
		} else if i < len(prior) &&
			!prior[i].Low.IsNull() && !prior[i].Low.IsUnknown() &&
			prior[i].Low.ValueInt64() == int64(port.GetLow()) &&
			!prior[i].High.IsNull() && !prior[i].High.IsUnknown() &&
			prior[i].High.ValueInt64() == 0 {
			model.High = prior[i].High
		}
		result = append(result, model)
	}
	return result
}

// NetworkFlowRulePortRangeModel describes a single ports block.
type NetworkFlowRulePortRangeModel struct {
	Low  types.Int64 `tfsdk:"low"`
	High types.Int64 `tfsdk:"high"`
}

func (r *NetworkFlowRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_network_flow_rule"
	// The rule ID (used as the identity) changes on every upsert, including
	// in-place updates, so the identity is mutable across the resource's life.
	resp.ResourceBehavior.MutableIdentity = true
}

func (r *NetworkFlowRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_network_flow_rule resource manages Network Flow Rules. Management of network flow rules requires the read:rules and write:rules permissions. Changing name or tag forces replacement; add a create_before_destroy lifecycle block to avoid a window where the rule does not exist.",
		MarkdownDescription: "The `nps_workshop_network_flow_rule` resource manages Network Flow Rules.\n\nManagement of network flow rules requires the `read:rules` and `write:rules` permissions.\n\nUpdates to non-key fields are applied atomically in place. Changing the rule's natural key (`name` or `tag`) forces the rule to be replaced: by default Terraform destroys the old rule before creating the new one, leaving a brief window with no rule in place. To avoid that window, add a `create_before_destroy` lifecycle block:\n\n```hcl\nresource \"nps_workshop_network_flow_rule\" \"example\" {\n  # ...\n  lifecycle {\n    create_before_destroy = true\n  }\n}\n```",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description:         "The name for this network flow rule. Rule names are unique per-tag.",
				MarkdownDescription: "The name for this network flow rule. Rule names are unique per-tag.",
				Required:            true,
				// Part of the natural key (tag, name). The upsert only supersedes the
				// old rule when the key matches, so changing the key must replace
				// rather than update in place.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"tag": schema.StringAttribute{
				Description:         "The tag for this network flow rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				MarkdownDescription: "The tag for this network flow rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				Required:            true,
				// Part of the natural key; see name.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"action": schema.StringAttribute{
				Description:         "The action to take on network flows matching this rule. The possible values are: NETWORK_FLOW_RULE_ACTION_ALLOW, NETWORK_FLOW_RULE_ACTION_DENY, NETWORK_FLOW_RULE_ACTION_SILENT_DENY, NETWORK_FLOW_RULE_ACTION_AUDIT.",
				MarkdownDescription: "The action to take on network flows matching this rule. The possible values are: `NETWORK_FLOW_RULE_ACTION_ALLOW`, `NETWORK_FLOW_RULE_ACTION_DENY`, `NETWORK_FLOW_RULE_ACTION_SILENT_DENY`, `NETWORK_FLOW_RULE_ACTION_AUDIT`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(apipb.NetworkFlowRuleAction(0).Descriptor())...),
				},
			},
			"direction": schema.StringAttribute{
				Description:         "The direction of network flows this rule applies to, relative to the host. The possible values are: NETWORK_FLOW_DIRECTION_ANY, NETWORK_FLOW_DIRECTION_OUTGOING, NETWORK_FLOW_DIRECTION_INCOMING.",
				MarkdownDescription: "The direction of network flows this rule applies to, relative to the host. The possible values are: `NETWORK_FLOW_DIRECTION_ANY`, `NETWORK_FLOW_DIRECTION_OUTGOING`, `NETWORK_FLOW_DIRECTION_INCOMING`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(apipb.NetworkFlowDirection(0).Descriptor())...),
				},
			},
			"priority": schema.BoolAttribute{
				Description:         "If true, this rule wins over all ranked rules. Mutually exclusive with rank.",
				MarkdownDescription: "If true, this rule wins over all ranked rules. Mutually exclusive with `rank`.",
				Optional:            true,
			},
			"rank": schema.Int64Attribute{
				Description:         "The precedence rank for this rule. A higher rank wins over lower-ranked rules. Mutually exclusive with priority. When neither is set the effective rank is 0.",
				MarkdownDescription: "The precedence rank for this rule. A higher rank wins over lower-ranked rules. Mutually exclusive with `priority`. When neither is set the effective rank is `0`.",
				Optional:            true,
			},
			"process_cd_hashes": schema.ListAttribute{
				Description:         "Process CDHashes that this rule applies to.",
				MarkdownDescription: "Process CDHashes that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"process_signing_ids": schema.ListAttribute{
				Description:         "Process signing IDs that this rule applies to.",
				MarkdownDescription: "Process signing IDs that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"process_team_ids": schema.ListAttribute{
				Description:         "Process team IDs that this rule applies to.",
				MarkdownDescription: "Process team IDs that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"remote_hostnames": schema.ListAttribute{
				Description:         "Remote hostnames that this rule applies to.",
				MarkdownDescription: "Remote hostnames that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"remote_domains": schema.ListAttribute{
				Description:         "Remote domains that this rule applies to.",
				MarkdownDescription: "Remote domains that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"remote_addresses": schema.ListAttribute{
				Description:         "Remote addresses that this rule applies to.",
				MarkdownDescription: "Remote addresses that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"protocols": schema.ListAttribute{
				Description:         "IANA protocol numbers (0-255) that this rule applies to. An empty list matches any protocol.",
				MarkdownDescription: "IANA protocol numbers (0-255) that this rule applies to. An empty list matches any protocol.",
				Optional:            true,
				ElementType:         types.Int64Type,
				Validators: []validator.List{
					listvalidator.ValueInt64sAre(int64validator.Between(0, 255)),
				},
			},
			"custom_msg": schema.StringAttribute{
				Description:         "A custom message to display to the user when this rule blocks a network flow.",
				MarkdownDescription: "A custom message to display to the user when this rule blocks a network flow.",
				Optional:            true,
			},
			"custom_url": schema.StringAttribute{
				Description:         "A custom URL to redirect the user to when this rule blocks a network flow.",
				MarkdownDescription: "A custom URL to redirect the user to when this rule blocks a network flow.",
				Optional:            true,
			},
			"comment": schema.StringAttribute{
				Description:         "A comment to add to this rule. Will be displayed in the Workshop UI.",
				MarkdownDescription: "A comment to add to this rule. Will be displayed in the Workshop UI.",
				Optional:            true,
			},

			// Computed value, returned from Create. The ID changes on every
			// upsert (including in-place updates), so it is intentionally left
			// without UseStateForUnknown: it plans as "known after apply"
			// whenever the rule changes.
			"id": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "The server-generated ID of this network flow rule. This ID is reassigned on every upsert, including in-place updates, so it must not be relied on as a stable identifier across applies.",
			},
		},

		Blocks: map[string]schema.Block{
			"ports": schema.ListNestedBlock{
				Description:         "Port ranges that this rule applies to. An empty list matches any port.",
				MarkdownDescription: "Port ranges that this rule applies to. An empty list matches any port.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"low": schema.Int64Attribute{
							Description:         "The inclusive lower bound of the port range.",
							MarkdownDescription: "The inclusive lower bound of the port range.",
							Required:            true,
							Validators: []validator.Int64{
								int64validator.Between(0, 65535),
							},
						},
						"high": schema.Int64Attribute{
							Description:         "The inclusive upper bound of the port range. Leave unset (or 0) to match only the low port.",
							MarkdownDescription: "The inclusive upper bound of the port range. Leave unset (or `0`) to match only the `low` port.",
							Optional:            true,
							Validators: []validator.Int64{
								int64validator.Between(0, 65535),
							},
						},
					},
				},
			},
		},
	}
}

func (r *NetworkFlowRuleResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		// priority and rank are the two arms of the precedence_hint oneof; at
		// most one may be set.
		resourcevalidator.Conflicting(
			path.MatchRoot("priority"),
			path.MatchRoot("rank"),
		),
	}
}

func (r *NetworkFlowRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *NetworkFlowRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data NetworkFlowRuleResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	rule := buildNetworkFlowRule(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	crResp, err := r.client.CreateNetworkFlowRule(ctx, apipb.CreateNetworkFlowRuleRequest_builder{
		Rule: rule,
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create network flow rule: %v", err))
		return
	}

	data.Id = types.Int64Value(crResp.GetRuleId())
	tflog.Info(ctx, fmt.Sprintf("Created network flow rule: %d", data.Id.ValueInt64()))

	// Set the identity
	resp.Diagnostics.Append(resp.Identity.Set(ctx, NetworkFlowRuleIdentityModel{Id: data.Id})...)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *NetworkFlowRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data NetworkFlowRuleResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Query for the rule by ID, name, and tag
	filter := fmt.Sprintf(`rule_id = %d OR (name = "%s" AND tag = "%s")`,
		data.Id.ValueInt64(), data.Name.ValueString(), data.Tag.ValueString())

	ret, err := r.client.ListNetworkFlowRules(ctx, apipb.ListNetworkFlowRulesRequest_builder{
		Filter:   proto.String(filter),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list network flow rules: %v", err))
		return
	}
	if len(ret.GetRules()) == 0 {
		// The rule was not found, remove it from the state so Terraform will offer
		// to create it.
		tflog.Info(ctx, fmt.Sprintf("Network flow rule %d not found", data.Id.ValueInt64()))
		resp.State.RemoveResource(ctx)
		return
	}

	// Now that we've found the rule, overwrite the state data with the actual
	// values retrieved via the API.
	rule := ret.GetRules()[0]
	priorPorts := data.Ports
	clearNetworkFlowRuleOptionalState(&data)
	data.Id = types.Int64Value(rule.GetRuleId())
	data.Tag = types.StringValue(rule.GetTag())
	data.Name = types.StringValue(rule.GetName())
	data.Action = types.StringValue(rule.GetAction().String())
	data.Direction = types.StringValue(rule.GetDirection().String())

	// precedence_hint oneof: only one arm is ever set.
	data.Priority = types.BoolNull()
	data.Rank = types.Int64Null()
	if rule.HasPriority() {
		data.Priority = types.BoolValue(rule.GetPriority())
	}
	if rule.HasRank() {
		data.Rank = types.Int64Value(rule.GetRank())
	}

	if rule.GetCustomMsg() != "" {
		data.CustomMsg = types.StringValue(rule.GetCustomMsg())
	}
	if rule.GetCustomUrl() != "" {
		data.CustomUrl = types.StringValue(rule.GetCustomUrl())
	}
	if rule.GetComment() != "" {
		data.Comment = types.StringValue(rule.GetComment())
	}

	// Convert slices to list types
	if len(rule.GetProcessCdHashes()) > 0 {
		data.ProcessCdHashes, _ = types.ListValueFrom(ctx, types.StringType, rule.GetProcessCdHashes())
	}
	if len(rule.GetProcessSigningIds()) > 0 {
		data.ProcessSigningIds, _ = types.ListValueFrom(ctx, types.StringType, rule.GetProcessSigningIds())
	}
	if len(rule.GetProcessTeamIds()) > 0 {
		data.ProcessTeamIds, _ = types.ListValueFrom(ctx, types.StringType, rule.GetProcessTeamIds())
	}
	if len(rule.GetRemoteHostnames()) > 0 {
		data.RemoteHostnames, _ = types.ListValueFrom(ctx, types.StringType, rule.GetRemoteHostnames())
	}
	if len(rule.GetRemoteDomains()) > 0 {
		data.RemoteDomains, _ = types.ListValueFrom(ctx, types.StringType, rule.GetRemoteDomains())
	}
	if len(rule.GetRemoteAddresses()) > 0 {
		data.RemoteAddresses, _ = types.ListValueFrom(ctx, types.StringType, rule.GetRemoteAddresses())
	}
	if len(rule.GetProtocols()) > 0 {
		protocols := make([]int64, 0, len(rule.GetProtocols()))
		for _, p := range rule.GetProtocols() {
			protocols = append(protocols, int64(p))
		}
		data.Protocols, _ = types.ListValueFrom(ctx, types.Int64Type, protocols)
	}
	data.Ports = networkFlowRulePortsFromProto(priorPorts, rule.GetPorts())

	// Set the identity
	resp.Diagnostics.Append(resp.Identity.Set(ctx, NetworkFlowRuleIdentityModel{Id: data.Id})...)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// buildNetworkFlowRule builds the (upsert) NetworkFlowRule from the model.
func buildNetworkFlowRule(ctx context.Context, data NetworkFlowRuleResourceModel, diags *diag.Diagnostics) *apipb.NetworkFlowRule {
	action := apipb.NetworkFlowRuleAction(apipb.NetworkFlowRuleAction_value[data.Action.ValueString()])
	direction := apipb.NetworkFlowDirection(apipb.NetworkFlowDirection_value[data.Direction.ValueString()])

	builder := apipb.NetworkFlowRule_builder{
		Tag:       data.Tag.ValueString(),
		Name:      data.Name.ValueString(),
		Action:    action,
		Direction: direction,
		CustomMsg: data.CustomMsg.ValueString(),
		CustomUrl: data.CustomUrl.ValueString(),
		Comment:   data.Comment.ValueString(),
	}

	// precedence_hint oneof: set at most one arm.
	if !data.Priority.IsNull() && !data.Priority.IsUnknown() {
		builder.Priority = proto.Bool(data.Priority.ValueBool())
	}
	if !data.Rank.IsNull() && !data.Rank.IsUnknown() {
		builder.Rank = proto.Int64(data.Rank.ValueInt64())
	}

	convertListHelper := func(v types.List, target *[]string) {
		if v.IsNull() || v.IsUnknown() {
			return
		}
		diags.Append(v.ElementsAs(ctx, target, false)...)
	}
	convertListHelper(data.ProcessCdHashes, &builder.ProcessCdHashes)
	convertListHelper(data.ProcessSigningIds, &builder.ProcessSigningIds)
	convertListHelper(data.ProcessTeamIds, &builder.ProcessTeamIds)
	convertListHelper(data.RemoteHostnames, &builder.RemoteHostnames)
	convertListHelper(data.RemoteDomains, &builder.RemoteDomains)
	convertListHelper(data.RemoteAddresses, &builder.RemoteAddresses)

	if !data.Protocols.IsNull() && !data.Protocols.IsUnknown() {
		var protocols []int64
		diags.Append(data.Protocols.ElementsAs(ctx, &protocols, false)...)
		for _, p := range protocols {
			builder.Protocols = append(builder.Protocols, uint32(p))
		}
	}

	for _, p := range data.Ports {
		builder.Ports = append(builder.Ports, apipb.NetworkFlowRule_PortRange_builder{
			Low:  uint32(p.Low.ValueInt64()),
			High: uint32(p.High.ValueInt64()),
		}.Build())
	}

	return builder.Build()
}

func (r *NetworkFlowRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan NetworkFlowRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newID, diags := r.upsertNetworkFlowRule(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if newID.IsNull() {
		return
	}
	plan.Id = newID
	tflog.Info(ctx, fmt.Sprintf("Updated network flow rule: %d", plan.Id.ValueInt64()))

	resp.Diagnostics.Append(resp.Identity.Set(ctx, NetworkFlowRuleIdentityModel{Id: plan.Id})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// upsertNetworkFlowRule performs an atomic update via the CreateNetworkFlowRule
// upsert RPC (keyed on (tag, name)) and returns the new rule ID. The server
// supersedes the existing rule sharing this key and returns a new ID, so the
// update is atomic and a failure leaves the old rule in place. The key
// attributes are RequiresReplace, so Update only ever changes non-key fields
// where the server is guaranteed to supersede; we never delete the old rule
// ourselves. Returns a null ID (with diagnostics) on failure.
func (r *NetworkFlowRuleResource) upsertNetworkFlowRule(ctx context.Context, plan NetworkFlowRuleResourceModel) (types.Int64, diag.Diagnostics) {
	var diags diag.Diagnostics

	rule := buildNetworkFlowRule(ctx, plan, &diags)
	if diags.HasError() {
		return types.Int64Null(), diags
	}

	crResp, err := r.client.CreateNetworkFlowRule(ctx, apipb.CreateNetworkFlowRuleRequest_builder{
		Rule: rule,
	}.Build())
	if err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to update network flow rule: %v", err))
		return types.Int64Null(), diags
	}
	return types.Int64Value(crResp.GetRuleId()), diags
}

func (r *NetworkFlowRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data NetworkFlowRuleResourceModel

	// Read Terraform prior state data into the model, which will give us the
	// rule ID to delete with.
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	ruleId := data.Id.ValueInt64()
	_, err := r.client.DeleteNetworkFlowRule(ctx, apipb.DeleteNetworkFlowRuleRequest_builder{
		RuleId: proto.Int64(ruleId),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete network flow rule: %v", err))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleted network flow rule: %d", ruleId))
}

func (r *NetworkFlowRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import a network flow rule by ID, which will trigger a Read.
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid ID", fmt.Sprintf("Failed to parse ID %q as integer: %v", req.ID, err))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func (r *NetworkFlowRuleResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.Int64Attribute{
				RequiredForImport: true,
			},
		},
	}
}

func NewNetworkFlowRuleListResource() list.ListResource {
	return &NetworkFlowRuleResource{}
}

func (r *NetworkFlowRuleResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "List all network flow rules in the Workshop instance.",
		Attributes:  map[string]listschema.Attribute{},
	}
}

func (r *NetworkFlowRuleResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	stream.Results = func(push func(list.ListResult) bool) {
		ret, err := r.client.ListNetworkFlowRules(ctx, apipb.ListNetworkFlowRulesRequest_builder{}.Build())
		if err != nil {
			result := req.NewListResult(ctx)
			result.Diagnostics.AddError("Client Error", "Failed to list network flow rules: "+err.Error())
			push(result)
			return
		}

		for _, rule := range ret.GetRules() {
			result := req.NewListResult(ctx)
			result.DisplayName = rule.GetName()

			result.Diagnostics.Append(result.Identity.Set(ctx, NetworkFlowRuleIdentityModel{
				Id: types.Int64Value(rule.GetRuleId()),
			})...)

			if req.IncludeResource {
				toListOrNull := func(slice []string) types.List {
					if len(slice) > 0 {
						l, _ := types.ListValueFrom(ctx, types.StringType, slice)
						return l
					}
					return types.ListNull(types.StringType)
				}

				model := NetworkFlowRuleResourceModel{
					Id:                types.Int64Value(rule.GetRuleId()),
					Tag:               types.StringValue(rule.GetTag()),
					Name:              types.StringValue(rule.GetName()),
					Action:            types.StringValue(rule.GetAction().String()),
					Direction:         types.StringValue(rule.GetDirection().String()),
					Priority:          types.BoolNull(),
					Rank:              types.Int64Null(),
					ProcessCdHashes:   toListOrNull(rule.GetProcessCdHashes()),
					ProcessSigningIds: toListOrNull(rule.GetProcessSigningIds()),
					ProcessTeamIds:    toListOrNull(rule.GetProcessTeamIds()),
					RemoteHostnames:   toListOrNull(rule.GetRemoteHostnames()),
					RemoteDomains:     toListOrNull(rule.GetRemoteDomains()),
					RemoteAddresses:   toListOrNull(rule.GetRemoteAddresses()),
					Protocols:         types.ListNull(types.Int64Type),
				}

				if rule.HasPriority() {
					model.Priority = types.BoolValue(rule.GetPriority())
				}
				if rule.HasRank() {
					model.Rank = types.Int64Value(rule.GetRank())
				}
				if rule.GetCustomMsg() != "" {
					model.CustomMsg = types.StringValue(rule.GetCustomMsg())
				}
				if rule.GetCustomUrl() != "" {
					model.CustomUrl = types.StringValue(rule.GetCustomUrl())
				}
				if rule.GetComment() != "" {
					model.Comment = types.StringValue(rule.GetComment())
				}
				if len(rule.GetProtocols()) > 0 {
					protocols := make([]int64, 0, len(rule.GetProtocols()))
					for _, p := range rule.GetProtocols() {
						protocols = append(protocols, int64(p))
					}
					model.Protocols, _ = types.ListValueFrom(ctx, types.Int64Type, protocols)
				}
				if len(rule.GetPorts()) > 0 {
					model.Ports = make([]NetworkFlowRulePortRangeModel, 0, len(rule.GetPorts()))
					for _, p := range rule.GetPorts() {
						port := NetworkFlowRulePortRangeModel{
							Low: types.Int64Value(int64(p.GetLow())),
						}
						if p.GetHigh() != 0 {
							port.High = types.Int64Value(int64(p.GetHigh()))
						}
						model.Ports = append(model.Ports, port)
					}
				}

				result.Diagnostics.Append(result.Resource.Set(ctx, model)...)
			}

			if !push(result) {
				return
			}
		}
	}
}
