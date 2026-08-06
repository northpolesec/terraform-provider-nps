// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/protobuf/proto"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &RulePackSubscriptionResource{}
var _ resource.ResourceWithConfigure = &RulePackSubscriptionResource{}
var _ resource.ResourceWithModifyPlan = &RulePackSubscriptionResource{}
var _ resource.ResourceWithImportState = &RulePackSubscriptionResource{}
var _ resource.ResourceWithIdentity = &RulePackSubscriptionResource{}
var _ list.ListResource = &RulePackSubscriptionResource{}
var _ list.ListResourceWithConfigure = &RulePackSubscriptionResource{}

func NewRulePackSubscriptionResource() resource.Resource {
	return &RulePackSubscriptionResource{}
}

func NewRulePackSubscriptionListResource() list.ListResource {
	return &RulePackSubscriptionResource{}
}

// RulePackSubscriptionResource defines the resource implementation.
type RulePackSubscriptionResource struct {
	client svcpb.WorkshopServiceClient
}

// RulePackSubscriptionIdentityModel describes the identity data model.
type RulePackSubscriptionIdentityModel struct {
	Id types.Int64 `tfsdk:"id"`
}

// RulePackSubscriptionResourceModel describes the resource data model.
type RulePackSubscriptionResourceModel struct {
	Id                    types.Int64  `tfsdk:"id"`
	RulePackId            types.String `tfsdk:"rule_pack_id"`
	RulePackTitle         types.String `tfsdk:"rule_pack_title"`
	Tags                  types.Set    `tfsdk:"tags"`
	CommitSha             types.String `tfsdk:"commit_sha"`
	MaterializedCommitSha types.String `tfsdk:"materialized_commit_sha"`
	LatestCommitSha       types.String `tfsdk:"latest_commit_sha"`
	SyncStatus            types.String `tfsdk:"sync_status"`
}

func (r *RulePackSubscriptionResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_rule_pack_subscription"
}

func (r *RulePackSubscriptionResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_rule_pack_subscription resource subscribes tags to a curated rule pack, identified by either rule_pack_id or rule_pack_title. Subscribing materializes the pack's rules as ordinary, editable Workshop rules, once per tag. Workshop allows only one subscription per pack, so one resource per pack lists every tag it applies to. Workshop does not adopt new pack versions on its own: to move to a newer version, set commit_sha to the version you reviewed. Leaving commit_sha unset pins the subscription to whatever version is already materialized, so Terraform never silently adopts an unreviewed version.",
		MarkdownDescription: "The `nps_workshop_rule_pack_subscription` resource subscribes tags to a curated rule pack. Subscribing materializes the pack's rules as ordinary, editable Workshop rules, once per tag in `tags`.\n\nName the pack with either `rule_pack_id` (its UUID) or `rule_pack_title` (its name in the catalog, resolved to a UUID at plan time).\n\nWorkshop allows only one subscription per rule pack. To apply a pack to several tags, list them all in this resource's `tags`; declaring a second resource for the same pack is an error, and the provider reports the subscription that already claims it.\n\nManagement of rule pack subscriptions requires the `read:rules` and `write:rules` permissions.\n\nWorkshop does not adopt new pack versions on its own. When a newer version is published, `latest_commit_sha` moves ahead of `materialized_commit_sha`; to adopt it, review that version and set `commit_sha` to it. Leaving `commit_sha` unset means Terraform never applies pack updates, so it can never silently adopt a version you have not reviewed. Workshop rejects the update if the published version moved on again after you reviewed it.\n\nRules that are edited in the Workshop UI detach from the subscription and are left alone from then on, so neither Workshop nor Terraform will overwrite a local edit.",

		Attributes: map[string]schema.Attribute{
			"rule_pack_id": schema.StringAttribute{
				Description:         "The UUID of the rule pack to subscribe to, as shown in the Workshop rule pack catalog. Exactly one of rule_pack_id or rule_pack_title must be set; when rule_pack_title is used this is the UUID it resolved to. Changing it forces replacement.",
				MarkdownDescription: "The UUID of the rule pack to subscribe to, as shown in the Workshop rule pack catalog. Exactly one of `rule_pack_id` or `rule_pack_title` must be set; when `rule_pack_title` is used this is the UUID it resolved to. Changing it forces replacement.",
				Optional:            true,
				Computed:            true,
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.MatchRoot("rule_pack_title")),
				},
				PlanModifiers: []planmodifier.String{
					// Hold the resolved UUID when the pack was selected by
					// title, so an unset rule_pack_id doesn't plan as unknown
					// and trip the RequiresReplace below on every apply.
					stringplanmodifier.UseStateForUnknown(),
					// A subscription tracks exactly one pack; there is no RPC
					// to repoint it at another one.
					stringplanmodifier.RequiresReplace(),
				},
			},
			"rule_pack_title": schema.StringAttribute{
				Description:         "The title of the rule pack to subscribe to, as shown in the Workshop rule pack catalog. Resolved to a UUID at plan time; a title matching zero or more than one available pack is an error. Exactly one of rule_pack_id or rule_pack_title must be set. Because the title is resolved before planning, following a pack that was renamed upstream is a no-op; only a title that resolves to a different pack forces replacement.",
				MarkdownDescription: "The title of the rule pack to subscribe to, as shown in the Workshop rule pack catalog. Resolved to a UUID at plan time; a title matching zero or more than one available pack is an error. Exactly one of `rule_pack_id` or `rule_pack_title` must be set.\n\nTitles are cosmetic pack metadata and can change upstream. Because the title is resolved to a UUID before planning, updating this to follow a pack that was renamed upstream plans as a no-op. Only a title that resolves to a *different* pack forces replacement, since a subscription cannot be repointed.",
				Optional:            true,
				// No RequiresReplace here: replacement is driven by the
				// resolved rule_pack_id, which ModifyPlan fills in.
			},
			"tags": schema.SetAttribute{
				Description:         "The tags to materialize the pack's rules under. One copy of each pack rule is created per tag. At least one tag is required. Workshop allows only one subscription per pack, so every tag the pack should apply to belongs in this one set. Changing the set re-materializes the rules in place, without replacing the subscription.",
				MarkdownDescription: "The tags to materialize the pack's rules under. One copy of each pack rule is created per tag. At least one tag is required.\n\nWorkshop allows only one subscription per rule pack, so every tag the pack should apply to belongs in this one set rather than in a second resource. Changing the set re-materializes the rules in place, without replacing the subscription.",
				Required:            true,
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
			},
			"commit_sha": schema.StringAttribute{
				Description:         "The pack version (rule-packs commit SHA) to materialize. Set this to latest_commit_sha once you have reviewed that version; Terraform then applies the update. Leave unset to never apply pack updates from Terraform.",
				MarkdownDescription: "The pack version (rule-packs commit SHA) to materialize. Set this to `latest_commit_sha` once you have reviewed that version; Terraform then applies the update. Leave unset to never apply pack updates from Terraform.\n\nWorkshop can only move a subscription to the currently published version, so `commit_sha` must be the latest published SHA. Pinning an older one is an error rather than a silent downgrade.",
				Optional:            true,
			},

			// Computed values, read back from the subscription.
			"id": schema.Int64Attribute{
				Description:         "The Workshop-local ID of this subscription.",
				MarkdownDescription: "The Workshop-local ID of this subscription.",
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"materialized_commit_sha": schema.StringAttribute{
				Description:         "The pack version whose rules are currently materialized.",
				MarkdownDescription: "The pack version whose rules are currently materialized.",
				Computed:            true,
			},
			"latest_commit_sha": schema.StringAttribute{
				Description:         "The latest published pack version Workshop has seen. When it differs from materialized_commit_sha an update is available.",
				MarkdownDescription: "The latest published pack version Workshop has seen. When it differs from `materialized_commit_sha` an update is available.",
				Computed:            true,
			},
			"sync_status": schema.StringAttribute{
				Description:         "The outcome of the last materialization, e.g. RULE_PACK_SUBSCRIPTION_SYNC_STATUS_SUCCESS.",
				MarkdownDescription: "The outcome of the last materialization, e.g. `RULE_PACK_SUBSCRIPTION_SYNC_STATUS_SUCCESS`.",
				Computed:            true,
			},
		},
	}
}

func (r *RulePackSubscriptionResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// ModifyPlan resolves rule_pack_title to a UUID before the plan is finalized,
// so that replacement is driven by the pack a title points at rather than by
// the title itself. A pack renamed upstream therefore plans as a no-op once the
// config follows the rename, instead of destroying and recreating every rule
// the subscription materialized; only a title that resolves to a different pack
// replaces, since a subscription cannot be repointed.
//
// Only the update path needs this: Create resolves the title itself, and there
// is nothing to resolve on destroy.
func (r *RulePackSubscriptionResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	// The provider isn't configured during `terraform validate`.
	if r.client == nil {
		return
	}

	var title types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("rule_pack_title"), &title)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Selected by UUID instead; rule_pack_id's own RequiresReplace covers it.
	if title.IsNull() {
		return
	}
	// If an expression keeps the title unknown until apply, there is no safe
	// way to prove that it still identifies the current pack. Conservatively
	// replace so Update cannot persist a new title alongside the old pack ID.
	if title.IsUnknown() {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("rule_pack_title"))
		return
	}

	pack, err := r.lookupPack(ctx, "", title.ValueString())
	if err != nil {
		// Fail the plan rather than warn: Update works from the subscription ID
		// and never re-resolves the title, so planning on an unverified title
		// risks quietly applying tag and version changes to whichever pack the
		// subscription used to track.
		resp.Diagnostics.AddAttributeError(
			path.Root("rule_pack_title"),
			"Failed to resolve rule pack title",
			err.Error(),
		)
		return
	}

	var stateID types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("rule_pack_id"), &stateID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Attribute plan modifiers have already run by now, so rule_pack_id holds
	// the prior state value (its config value is null when a title is used).
	// Overwrite it with what the title resolves to today.
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("rule_pack_id"), types.StringValue(pack.GetId()))...)
	if pack.GetId() != stateID.ValueString() {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("rule_pack_id"))
	}
}

// applySubscription overwrites the computed fields of data with the server's
// view of the subscription. commit_sha and rule_pack_title are deliberately
// untouched: they are operator inputs (the version reviewed, and how the pack
// was named) rather than mirrors of server state, and Terraform requires them
// to keep matching the configuration. Leaving rule_pack_title null also keeps
// generated config down to just the resolved rule_pack_id, which the
// exactly-one-of constraint requires.
func applySubscription(ctx context.Context, data *RulePackSubscriptionResourceModel, sub *apipb.RulePackSubscription, diags *diag.Diagnostics) {
	// Every field below would silently become a zero value, so refuse rather
	// than write a subscription with ID 0 into state.
	if sub == nil {
		diags.AddError("Client Error", "Workshop returned no subscription. Please report this issue to the provider developers.")
		return
	}

	tags, d := types.SetValueFrom(ctx, types.StringType, sub.GetTags())
	diags.Append(d...)

	data.Id = types.Int64Value(sub.GetId())
	data.RulePackId = types.StringValue(sub.GetRulePackId())
	data.Tags = tags
	data.MaterializedCommitSha = types.StringValue(sub.GetMaterializedCommitSha())
	data.LatestCommitSha = types.StringValue(sub.GetLatestCommitSha())
	data.SyncStatus = types.StringValue(sub.GetSyncStatusCode().String())
}

// warnPartialSync surfaces a non-SUCCESS materialization as a warning rather
// than an error: the subscription exists and most of its rules are usually in
// place, so failing the apply would be worse than reporting it.
func warnPartialSync(sub *apipb.RulePackSubscription, diags *diag.Diagnostics) {
	status := sub.GetSyncStatusCode()
	if status == apipb.RulePackSubscriptionSyncStatus_RULE_PACK_SUBSCRIPTION_SYNC_STATUS_SUCCESS {
		return
	}
	diags.AddWarning(
		"Rule pack did not fully materialize",
		fmt.Sprintf("Subscription %d reports sync status %s. Inspect the subscription in Workshop to see which rules were rejected, unsupported, or skipped.", sub.GetId(), status),
	)
}

// resolvePack finds the single available pack identified by either its UUID or
// its catalog title. Exactly one of id/title is non-empty (enforced by the
// schema). Titles aren't guaranteed unique, so an ambiguous one is an error
// rather than an arbitrary pick.
func resolvePack(packs []*apipb.RulePack, id, title string) (*apipb.RulePack, error) {
	var matches []*apipb.RulePack
	for _, p := range packs {
		if (id != "" && p.GetId() == id) || (title != "" && p.GetTitle() == title) {
			matches = append(matches, p)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		if id != "" {
			return nil, fmt.Errorf("no rule pack with id %q is available to this Workshop instance", id)
		}
		return nil, fmt.Errorf("no rule pack titled %q is available to this Workshop instance", title)
	default:
		return nil, fmt.Errorf("%d available rule packs are titled %q; use rule_pack_id to pick one", len(matches), title)
	}
}

// existingSubscription returns the tenant's subscription to the given pack, or
// nil if there isn't one. Workshop enforces at most one per pack, so a single
// filtered result is the whole answer.
func (r *RulePackSubscriptionResource) existingSubscription(ctx context.Context, packID string) (*apipb.RulePackSubscription, error) {
	ret, err := r.client.ListRulePackSubscriptions(ctx, apipb.ListRulePackSubscriptionsRequest_builder{
		Filter:   proto.String(fmt.Sprintf("rule_pack_id = %q", packID)),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		return nil, fmt.Errorf("failed to list rule pack subscriptions: %w", err)
	}
	if subs := ret.GetSubscriptions(); len(subs) > 0 {
		return subs[0], nil
	}
	return nil, nil
}

// lookupPack resolves the configured pack against the live catalog.
func (r *RulePackSubscriptionResource) lookupPack(ctx context.Context, id, title string) (*apipb.RulePack, error) {
	ret, err := r.client.ListAvailableRulePacks(ctx, apipb.ListAvailableRulePacksRequest_builder{}.Build())
	if err != nil {
		return nil, fmt.Errorf("failed to list available rule packs: %w", err)
	}
	return resolvePack(ret.GetRulePacks(), id, title)
}

func (r *RulePackSubscriptionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RulePackSubscriptionResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve the pack up front: it turns a title into the UUID that
	// SubscribeToRulePack needs, and it catches a bad reference before we
	// create anything.
	pack, err := r.lookupPack(ctx, data.RulePackId.ValueString(), data.RulePackTitle.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to resolve rule pack: %v", err))
		return
	}
	packID := pack.GetId()

	// Subscribing always materializes whatever version is published, so a
	// commit_sha that isn't the published one can't be honoured. Check before
	// subscribing rather than after, so a mismatch doesn't leave an orphan
	// subscription behind.
	if !data.CommitSha.IsNull() && !data.CommitSha.IsUnknown() && pack.GetCommitSha() != data.CommitSha.ValueString() {
		resp.Diagnostics.AddAttributeError(
			path.Root("commit_sha"),
			"Rule pack version mismatch",
			fmt.Sprintf("commit_sha is %q but rule pack %q is published at %q. Subscribing materializes the published version; review it and set commit_sha to %q, or remove commit_sha.", data.CommitSha.ValueString(), packID, pack.GetCommitSha(), pack.GetCommitSha()),
		)
		return
	}

	// Workshop permits only one subscription per pack, so a second resource
	// pointing at the same pack can never be created. Say so in terms of the
	// existing subscription instead of passing the server's rejection through.
	if existing, err := r.existingSubscription(ctx, packID); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to check for an existing subscription to rule pack %q: %v", packID, err))
		return
	} else if existing != nil {
		resp.Diagnostics.AddError(
			"Rule pack is already subscribed",
			fmt.Sprintf(
				"Rule pack %q (%s) is already subscribed by subscription %d, materialized under tag(s) %s. Workshop allows only one subscription per pack.\n\n"+
					"If another nps_workshop_rule_pack_subscription resource manages that subscription, add these tags to its tags attribute instead of declaring a second resource. Otherwise adopt the existing subscription:\n\n"+
					"  terraform import <resource address> %d",
				pack.GetTitle(), packID, existing.GetId(), strings.Join(existing.GetTags(), ", "), existing.GetId(),
			),
		)
		return
	}

	var tags []string
	resp.Diagnostics.Append(data.Tags.ElementsAs(ctx, &tags, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ret, err := r.client.SubscribeToRulePack(ctx, apipb.SubscribeToRulePackRequest_builder{
		RulePackId: proto.String(packID),
		Tags:       tags,
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to subscribe to rule pack %q: %v", packID, err))
		return
	}

	sub := ret.GetSubscription()
	applySubscription(ctx, &data, sub, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	warnPartialSync(sub, &resp.Diagnostics)
	tflog.Info(ctx, fmt.Sprintf("Subscribed to rule pack %q: subscription %d", packID, sub.GetId()))

	resp.Diagnostics.Append(resp.Identity.Set(ctx, RulePackSubscriptionIdentityModel{Id: data.Id})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RulePackSubscriptionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RulePackSubscriptionResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := data.Id.ValueInt64()
	ret, err := r.client.GetRulePackSubscription(ctx, apipb.GetRulePackSubscriptionRequest_builder{
		SubscriptionId: proto.Int64(id),
	}.Build())
	if err != nil {
		if isDeleteNoOp(err) {
			tflog.Info(ctx, fmt.Sprintf("Rule pack subscription %d not found", id))
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get rule pack subscription %d: %v", id, err))
		return
	}

	applySubscription(ctx, &data, ret.GetSubscription(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, RulePackSubscriptionIdentityModel{Id: data.Id})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// shouldApplyVersion reports whether Update should move the subscription to a
// new pack version. This is the anti-stomp guard: an unset commit_sha means
// "leave the materialized version alone", so Terraform never adopts a version
// nobody reviewed, and a commit_sha that already matches is a no-op rather than
// a pointless re-materialization.
func shouldApplyVersion(commitSha types.String, materialized string) bool {
	if commitSha.IsNull() || commitSha.IsUnknown() {
		return false
	}
	return commitSha.ValueString() != materialized
}

// Update reconciles the two things a subscription can change in place: the tag
// its rules are materialized under, and the pack version. rule_pack_id is
// RequiresReplace, so it never reaches here.
func (r *RulePackSubscriptionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state RulePackSubscriptionResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.Id.ValueInt64()
	sub := (*apipb.RulePackSubscription)(nil)

	if !plan.Tags.Equal(state.Tags) {
		var tags []string
		resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		ret, err := r.client.UpdateRulePackSubscriptionTags(ctx, apipb.UpdateRulePackSubscriptionTagsRequest_builder{
			SubscriptionId: proto.Int64(id),
			Tags:           tags,
		}.Build())
		if err != nil {
			// Nothing changed server-side, so leave state alone and let the
			// next plan retry.
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update tags on rule pack subscription %d: %v", id, err))
			return
		}
		sub = ret.GetSubscription()
	}

	wantSha := plan.CommitSha.ValueString()
	if shouldApplyVersion(plan.CommitSha, state.MaterializedCommitSha.ValueString()) {
		ret, err := r.client.ApplyRulePackUpdate(ctx, apipb.ApplyRulePackUpdateRequest_builder{
			SubscriptionId: proto.Int64(id),
			// Workshop rejects the update if the published version has moved
			// past this SHA, so we can't adopt something unreviewed.
			ExpectedLatestCommitSha: proto.String(wantSha),
		}.Build())
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to apply rule pack update to subscription %d: %v. Workshop only moves a subscription to the currently published version; check latest_commit_sha, review that version, and set commit_sha to it.", id, err))
			// A preceding tag change may have succeeded, so persist whatever we
			// last saw. commit_sha stays at its prior value so the next plan
			// still shows the pending version change.
			if sub != nil {
				applySubscription(ctx, &state, sub, &resp.Diagnostics)
				resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			}
			return
		}
		sub = ret.GetSubscription()
	}

	// Terraform marks every computed attribute without UseStateForUnknown as
	// unknown in the plan as soon as anything changes, so the plan can never be
	// written to state as-is. When neither branch above had an RPC to make (for
	// example commit_sha was set to the version already materialized), read the
	// subscription back so those values are known.
	if sub == nil {
		ret, err := r.client.GetRulePackSubscription(ctx, apipb.GetRulePackSubscriptionRequest_builder{
			SubscriptionId: proto.Int64(id),
		}.Build())
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get rule pack subscription %d: %v", id, err))
			return
		}
		sub = ret.GetSubscription()
	}

	applySubscription(ctx, &plan, sub, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	warnPartialSync(sub, &resp.Diagnostics)
	tflog.Info(ctx, fmt.Sprintf("Updated rule pack subscription %d", id))

	resp.Diagnostics.Append(resp.Identity.Set(ctx, RulePackSubscriptionIdentityModel{Id: plan.Id})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RulePackSubscriptionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RulePackSubscriptionResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := data.Id.ValueInt64()
	_, err := r.client.UnsubscribeFromRulePack(ctx, apipb.UnsubscribeFromRulePackRequest_builder{
		SubscriptionId: proto.Int64(id),
	}.Build())
	if err != nil && !isDeleteNoOp(err) {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to unsubscribe from rule pack (subscription %d): %v", id, err))
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Unsubscribed from rule pack: subscription %d", id))
}

func (r *RulePackSubscriptionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var id types.Int64
	if req.ID != "" {
		parsedID, err := strconv.ParseInt(req.ID, 10, 64)
		if err != nil {
			resp.Diagnostics.AddError("Invalid ID", fmt.Sprintf("Failed to parse ID %q as integer: %v", req.ID, err))
			return
		}
		id = types.Int64Value(parsedID)
	} else {
		if req.Identity == nil {
			resp.Diagnostics.AddError("Missing Identity", "Import requires either an integer ID or an identity containing id.")
			return
		}
		resp.Diagnostics.Append(req.Identity.GetAttribute(ctx, path.Root("id"), &id)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func (r *RulePackSubscriptionResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.Int64Attribute{
				RequiredForImport: true,
			},
		},
	}
}

func (r *RulePackSubscriptionResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "List all rule pack subscriptions in the Workshop instance.",
		Attributes:  map[string]listschema.Attribute{},
	}
}

func (r *RulePackSubscriptionResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	stream.Results = func(push func(list.ListResult) bool) {
		ret, err := r.client.ListRulePackSubscriptions(ctx, apipb.ListRulePackSubscriptionsRequest_builder{}.Build())
		if err != nil {
			result := req.NewListResult(ctx)
			result.Diagnostics.AddError("Client Error", "Failed to list rule pack subscriptions: "+err.Error())
			push(result)
			return
		}

		for _, sub := range ret.GetSubscriptions() {
			result := req.NewListResult(ctx)
			result.DisplayName = sub.GetTitle()

			result.Diagnostics.Append(result.Identity.Set(ctx, RulePackSubscriptionIdentityModel{
				Id: types.Int64Value(sub.GetId()),
			})...)

			if req.IncludeResource {
				var model RulePackSubscriptionResourceModel
				applySubscription(ctx, &model, sub, &result.Diagnostics)
				result.Diagnostics.Append(result.Resource.Set(ctx, model)...)
			}

			if !push(result) {
				return
			}
		}
	}
}
