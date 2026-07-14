// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &SyncSettingsResource{}
var _ resource.ResourceWithConfigure = &SyncSettingsResource{}
var _ resource.ResourceWithImportState = &SyncSettingsResource{}
var _ resource.ResourceWithIdentity = &SyncSettingsResource{}
var _ resource.ResourceWithConfigValidators = &SyncSettingsResource{}
var _ resource.ResourceWithModifyPlan = &SyncSettingsResource{}

func NewSyncSettingsResource() resource.Resource {
	return &SyncSettingsResource{}
}

type SyncSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type SyncSettingsIdentityModel struct {
	Tag types.String `tfsdk:"tag"`
}

type SyncSettingsResourceModel struct {
	Tag types.String `tfsdk:"tag"`

	ClientMode                 types.String `tfsdk:"client_mode"`
	EnableTransitiveRules      types.Bool   `tfsdk:"enable_transitive_rules"`
	TelemetryEnabled           types.Bool   `tfsdk:"telemetry_enabled"`
	NetworkExtensionEnabled    types.Bool   `tfsdk:"network_extension_enabled"`
	AllowedPathRegex           types.String `tfsdk:"allowed_path_regex"`
	BlockedPathRegex           types.String `tfsdk:"blocked_path_regex"`
	FullSyncInterval           types.Int64  `tfsdk:"full_sync_interval"`
	PushSyncInterval           types.Int64  `tfsdk:"push_sync_interval"`
	TelemetryFilterExpressions types.List   `tfsdk:"telemetry_filter_expressions"`

	CelFallbackRule               []SyncSettingsCelFallbackRuleModel     `tfsdk:"cel_fallback_rule"`
	OnDemandMonitorMode           *SyncSettingsOnDemandMonitorModeModel  `tfsdk:"on_demand_monitor_mode"`
	NetworkMount                  *SyncSettingsNetworkMountModel         `tfsdk:"network_mount"`
	RemovableMediaPolicy          *SyncSettingsRemovableMediaPolicyModel `tfsdk:"removable_media_policy"`
	EncryptedRemovableMediaPolicy *SyncSettingsRemovableMediaPolicyModel `tfsdk:"encrypted_removable_media_policy"`
}

type SyncSettingsCelFallbackRuleModel struct {
	Expression types.String `tfsdk:"expression"`
	CustomMsg  types.String `tfsdk:"custom_msg"`
	CustomURL  types.String `tfsdk:"custom_url"`
}

type SyncSettingsOnDemandMonitorModeModel struct {
	State                  types.String `tfsdk:"state"`
	MaxMinutes             types.Int64  `tfsdk:"max_minutes"`
	DefaultDurationMinutes types.Int64  `tfsdk:"default_duration_minutes"`
}

type SyncSettingsNetworkMountModel struct {
	BlockMount    types.String `tfsdk:"block_mount"`
	BannedMessage types.String `tfsdk:"banned_message"`
	AllowedHosts  types.List   `tfsdk:"allowed_hosts"`
}

type SyncSettingsRemovableMediaPolicyModel struct {
	Action       types.String `tfsdk:"action"`
	RemountFlags types.List   `tfsdk:"remount_flags"`
}

var (
	syncSettingsClientModeValues        = []string{"MONITOR", "LOCKDOWN", "STANDALONE"}
	syncSettingsOnDemandModeStateValues = []string{
		"ON_DEMAND_MONITOR_MODE_STATE_ENABLED",
		"ON_DEMAND_MONITOR_MODE_STATE_DISABLED",
	}
	syncSettingsNetworkMountBlockMountValues = []string{
		"BLOCK_MOUNT_ENABLED",
		"BLOCK_MOUNT_DISABLED",
	}
	syncSettingsRemovableActionValues = []string{"ALLOW", "BLOCK", "REMOUNT"}

	// syncSettingsTagRegex mirrors the server-side tag validation
	// (letters, digits, '.', ':', '-', '_'). Enforcing it here gives early
	// feedback and ensures the tag cannot break out of the ListSyncSettings /
	// ListTelemetryConfigs filter string it is interpolated into.
	syncSettingsTagRegex = regexp.MustCompile(`^[\p{L}\p{N}.:_-]+$`)
)

func (r *SyncSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_sync_settings"
}

func (r *SyncSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_sync_settings resource manages Santa sync settings for a single tag. Attributes that are unset in the configuration are not sent to the server and lower-precedence tags continue to apply. Attributes explicitly set to an empty value override lower-precedence tags with that empty value. The resource performs a delete-and-replace on every apply, so the server state always reflects the Terraform configuration exactly.",
		MarkdownDescription: "The `nps_workshop_sync_settings` resource manages Santa sync settings for a single tag. Attributes that are unset in the configuration are not sent to the server and lower-precedence tags continue to apply. Attributes explicitly set to an empty value override lower-precedence tags with that empty value. The resource performs a delete-and-replace on every apply, so the server state always reflects the Terraform configuration exactly.\n\nWhen the managed tag is `global`, deleting on the server re-seeds defaults; this resource is intended primarily for non-global tags.",

		Attributes: map[string]schema.Attribute{
			"tag": schema.StringAttribute{
				Description:         "The tag whose sync settings this resource manages. Changing the tag forces replacement. May contain only letters, digits, periods, colons, hyphens, and underscores (max 42 characters).",
				MarkdownDescription: "The tag whose sync settings this resource manages. Changing the tag forces replacement. May contain only letters, digits, periods, colons, hyphens, and underscores (max 42 characters).",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 42),
					stringvalidator.RegexMatches(
						syncSettingsTagRegex,
						"must contain only letters, digits, periods, colons, hyphens, and underscores",
					),
				},
			},
			"client_mode": schema.StringAttribute{
				Description:         "Santa client mode for hosts in this tag. One of: MONITOR, LOCKDOWN, STANDALONE.",
				MarkdownDescription: "Santa client mode for hosts in this tag. One of: `MONITOR`, `LOCKDOWN`, `STANDALONE`.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(syncSettingsClientModeValues...),
				},
			},
			"enable_transitive_rules": schema.BoolAttribute{
				Description:         "Whether transitive rule creation is enabled.",
				MarkdownDescription: "Whether transitive rule creation is enabled.",
				Optional:            true,
			},
			"telemetry_enabled": schema.BoolAttribute{
				Description:         "Whether telemetry upload is enabled for hosts in this tag. Backed by the tag's TelemetryConfig (managed via the UpdateTelemetryConfig RPC), not by SyncSettings. Leaving it unset removes any TelemetryConfig for the tag so a lower-precedence tag applies. Requires the telemetry feature to be enabled for the tenant.",
				MarkdownDescription: "Whether telemetry upload is enabled for hosts in this tag. Backed by the tag's `TelemetryConfig` (managed via the `UpdateTelemetryConfig` RPC), not by `SyncSettings`. Leaving it unset removes any `TelemetryConfig` for the tag so a lower-precedence tag applies. Requires the telemetry feature to be enabled for the tenant.",
				Optional:            true,
			},
			"network_extension_enabled": schema.BoolAttribute{
				Description:         "Whether the Santa network extension is enabled.",
				MarkdownDescription: "Whether the Santa network extension is enabled.",
				Optional:            true,
			},
			"allowed_path_regex": schema.StringAttribute{
				Description:         "Regex matching paths whose executions are allowed. Set to an empty string to explicitly clear any lower-precedence tag's value.",
				MarkdownDescription: "Regex matching paths whose executions are allowed. Set to an empty string to explicitly clear any lower-precedence tag's value.",
				Optional:            true,
			},
			"blocked_path_regex": schema.StringAttribute{
				Description:         "Regex matching paths whose executions are blocked. Set to an empty string to explicitly clear any lower-precedence tag's value.",
				MarkdownDescription: "Regex matching paths whose executions are blocked. Set to an empty string to explicitly clear any lower-precedence tag's value.",
				Optional:            true,
			},
			"full_sync_interval": schema.Int64Attribute{
				Description:         "Seconds between full syncs. Must be between 60 and 86400 when set.",
				MarkdownDescription: "Seconds between full syncs. Must be between `60` and `86400` when set.",
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(60, 86400),
				},
			},
			"push_sync_interval": schema.Int64Attribute{
				Description:         "Seconds between full syncs requested via push notifications (proto field push_notification_full_sync_interval_seconds). Must be between 60 and 86400 when set.",
				MarkdownDescription: "Seconds between full syncs requested via push notifications (proto field `push_notification_full_sync_interval_seconds`). Must be between `60` and `86400` when set.",
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(60, 86400),
				},
			},
			"telemetry_filter_expressions": schema.ListAttribute{
				Description:         "CEL expressions filtering telemetry events. Unset leaves the field unspecified (lower-precedence tag applies); an empty list explicitly clears the inherited value.",
				MarkdownDescription: "CEL expressions filtering telemetry events. Unset leaves the field unspecified (lower-precedence tag applies); an empty list explicitly clears the inherited value.",
				Optional:            true,
				ElementType:         types.StringType,
			},
		},

		Blocks: map[string]schema.Block{
			"cel_fallback_rule": schema.ListNestedBlock{
				Description:         "CEL fallback rules evaluated when no static rule matches. The block may be repeated; the order is preserved.",
				MarkdownDescription: "CEL fallback rules evaluated when no static rule matches. The block may be repeated; the order is preserved.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"expression": schema.StringAttribute{
							Description:         "CEL expression evaluated against the execution. Must return UNSPECIFIED on at least one branch.",
							MarkdownDescription: "CEL expression evaluated against the execution. Must return `UNSPECIFIED` on at least one branch.",
							Required:            true,
						},
						"custom_msg": schema.StringAttribute{
							Description:         "Optional custom message shown to the user when the rule blocks.",
							MarkdownDescription: "Optional custom message shown to the user when the rule blocks.",
							Optional:            true,
						},
						"custom_url": schema.StringAttribute{
							Description:         "Optional custom URL shown to the user when the rule blocks.",
							MarkdownDescription: "Optional custom URL shown to the user when the rule blocks.",
							Optional:            true,
						},
					},
				},
			},
			"on_demand_monitor_mode": schema.SingleNestedBlock{
				Description:         "On-demand monitor mode settings.",
				MarkdownDescription: "On-demand monitor mode settings.",
				Attributes: map[string]schema.Attribute{
					"state": schema.StringAttribute{
						Description:         "Whether on-demand monitor mode is enabled. One of: ON_DEMAND_MONITOR_MODE_STATE_ENABLED, ON_DEMAND_MONITOR_MODE_STATE_DISABLED.",
						MarkdownDescription: "Whether on-demand monitor mode is enabled. One of: `ON_DEMAND_MONITOR_MODE_STATE_ENABLED`, `ON_DEMAND_MONITOR_MODE_STATE_DISABLED`.",
						Optional:            true,
						Validators: []validator.String{
							stringvalidator.OneOf(syncSettingsOnDemandModeStateValues...),
						},
					},
					"max_minutes": schema.Int64Attribute{
						Description:         "Maximum number of minutes a machine may be in monitor mode. Required when state is ENABLED.",
						MarkdownDescription: "Maximum number of minutes a machine may be in monitor mode. Required when `state` is `ENABLED`.",
						Optional:            true,
						Validators: []validator.Int64{
							int64validator.Between(1, 60*24*30),
						},
					},
					"default_duration_minutes": schema.Int64Attribute{
						Description:         "Default monitor-mode duration when the host requests entry without specifying one. Must not exceed max_minutes. Omit (rather than set 0) to fall back to max_minutes as the default.",
						MarkdownDescription: "Default monitor-mode duration when the host requests entry without specifying one. Must not exceed `max_minutes`. Omit (rather than set `0`) to fall back to `max_minutes` as the default.",
						Optional:            true,
						Validators: []validator.Int64{
							int64validator.AtLeast(1),
						},
					},
				},
			},
			"network_mount": schema.SingleNestedBlock{
				Description:         "Network mount handling settings.",
				MarkdownDescription: "Network mount handling settings.",
				Attributes: map[string]schema.Attribute{
					"block_mount": schema.StringAttribute{
						Description:         "Whether network mounts are blocked. One of: BLOCK_MOUNT_ENABLED, BLOCK_MOUNT_DISABLED.",
						MarkdownDescription: "Whether network mounts are blocked. One of: `BLOCK_MOUNT_ENABLED`, `BLOCK_MOUNT_DISABLED`.",
						Optional:            true,
						Validators: []validator.String{
							stringvalidator.OneOf(syncSettingsNetworkMountBlockMountValues...),
						},
					},
					"banned_message": schema.StringAttribute{
						Description:         "Message shown to the user when a network mount is blocked.",
						MarkdownDescription: "Message shown to the user when a network mount is blocked.",
						Optional:            true,
					},
					"allowed_hosts": schema.ListAttribute{
						Description:         "Hosts whose network mounts are permitted even when block_mount is enabled. Unset leaves the field unspecified; an empty list explicitly clears the inherited value.",
						MarkdownDescription: "Hosts whose network mounts are permitted even when `block_mount` is enabled. Unset leaves the field unspecified; an empty list explicitly clears the inherited value.",
						Optional:            true,
						ElementType:         types.StringType,
					},
				},
			},
			"removable_media_policy":           removableMediaPolicyBlockSchema("Baseline removable-media policy applied to every mount."),
			"encrypted_removable_media_policy": removableMediaPolicyBlockSchema("Override removable-media policy for encrypted volumes. If unset, encrypted volumes follow removable_media_policy."),
		},
	}
}

func removableMediaPolicyBlockSchema(desc string) schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description:         desc,
		MarkdownDescription: desc,
		Attributes: map[string]schema.Attribute{
			"action": schema.StringAttribute{
				Description:         "Policy action. One of: ALLOW, BLOCK, REMOUNT. When REMOUNT, remount_flags specifies the mount flags to apply.",
				MarkdownDescription: "Policy action. One of: `ALLOW`, `BLOCK`, `REMOUNT`. When `REMOUNT`, `remount_flags` specifies the mount flags to apply.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(syncSettingsRemovableActionValues...),
				},
			},
			"remount_flags": schema.ListAttribute{
				Description:         "Mount flags applied when action is REMOUNT (e.g. [\"nodev\", \"nosuid\"]).",
				MarkdownDescription: "Mount flags applied when `action` is `REMOUNT` (e.g. `[\"nodev\", \"nosuid\"]`).",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(0),
				},
			},
		},
	}
}

func (r *SyncSettingsResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		utils.ConfigValidatorFunc("Validate removable-media policy blocks", func(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
			var data SyncSettingsResourceModel
			resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
			if resp.Diagnostics.HasError() {
				return
			}
			validateRemovablePolicyBlock(path.Root("removable_media_policy"), data.RemovableMediaPolicy, &resp.Diagnostics)
			validateRemovablePolicyBlock(path.Root("encrypted_removable_media_policy"), data.EncryptedRemovableMediaPolicy, &resp.Diagnostics)
		}),
		utils.ConfigValidatorFunc("Validate on_demand_monitor_mode", func(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
			var data SyncSettingsResourceModel
			resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
			if resp.Diagnostics.HasError() {
				return
			}
			odmm := data.OnDemandMonitorMode
			if odmm == nil {
				return
			}
			if odmm.State.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("on_demand_monitor_mode").AtName("state"),
					"state is required",
					"state must be set when the on_demand_monitor_mode block is present",
				)
			}
			if odmm.State.ValueString() == "ON_DEMAND_MONITOR_MODE_STATE_ENABLED" && odmm.MaxMinutes.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("on_demand_monitor_mode").AtName("max_minutes"),
					"max_minutes is required",
					"max_minutes must be set when state is ON_DEMAND_MONITOR_MODE_STATE_ENABLED",
				)
			}
			if !odmm.MaxMinutes.IsNull() && !odmm.DefaultDurationMinutes.IsNull() &&
				odmm.DefaultDurationMinutes.ValueInt64() > odmm.MaxMinutes.ValueInt64() {
				resp.Diagnostics.AddAttributeError(
					path.Root("on_demand_monitor_mode").AtName("default_duration_minutes"),
					"default_duration_minutes exceeds max_minutes",
					"default_duration_minutes must not exceed max_minutes",
				)
			}
		}),
	}
}

func validateRemovablePolicyBlock(p path.Path, m *SyncSettingsRemovableMediaPolicyModel, diags *diag.Diagnostics) {
	if m == nil {
		return
	}
	if m.Action.IsNull() {
		diags.AddAttributeError(
			p.AtName("action"),
			"action is required",
			"action must be set when the policy block is present",
		)
		return
	}
	action := m.Action.ValueString()
	hasFlags := !m.RemountFlags.IsNull() && !m.RemountFlags.IsUnknown()
	if action == "REMOUNT" && !hasFlags {
		diags.AddAttributeError(
			p.AtName("remount_flags"),
			"remount_flags is required",
			"remount_flags must be set when action is REMOUNT",
		)
	}
	if action != "REMOUNT" && hasFlags {
		diags.AddAttributeError(
			p.AtName("remount_flags"),
			"remount_flags is only valid when action is REMOUNT",
			"remount_flags must not be set unless action is REMOUNT",
		)
	}
}

func (r *SyncSettingsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// No plan to validate on destroy, and the client may be unset if the
	// provider isn't fully configured (e.g. during validate).
	if req.Plan.Raw.IsNull() || r.client == nil {
		return
	}

	var data SyncSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.validateCelFallbackRules(ctx, data.CelFallbackRule, &resp.Diagnostics)
}

func (r *SyncSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SyncSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SyncSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create: no prior state, so pass a null prior telemetry value.
	if !r.replaceTagSettings(ctx, &data, types.BoolNull(), &resp.Diagnostics) {
		return
	}

	tflog.Info(ctx, "Created sync settings", map[string]any{"tag": data.Tag.ValueString()})

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SyncSettingsIdentityModel{Tag: data.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SyncSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SyncSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ss, found, err := r.fetchSyncSettings(ctx, data.Tag.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list sync settings: %v", err))
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	newData, d := syncSettingsProtoToModel(ctx, ss)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	newData.TelemetryEnabled = r.fetchTelemetryEnabled(ctx, data.Tag.ValueString())

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SyncSettingsIdentityModel{Tag: newData.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &newData)...)
}

func (r *SyncSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data, state SyncSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.replaceTagSettings(ctx, &data, state.TelemetryEnabled, &resp.Diagnostics) {
		return
	}

	tflog.Info(ctx, "Updated sync settings", map[string]any{"tag": data.Tag.ValueString()})

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SyncSettingsIdentityModel{Tag: data.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SyncSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data SyncSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	delReq := apipb.DeleteSyncSettingsRequest_builder{Tag: proto.String(data.Tag.ValueString())}.Build()
	if _, err := r.client.DeleteSyncSettings(ctx, delReq); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete sync settings for tag %q: %v", data.Tag.ValueString(), err))
		return
	}

	// Only remove the TelemetryConfig if this resource was managing it, to
	// avoid calling the feature-gated telemetry RPC for tags that never set it.
	if !data.TelemetryEnabled.IsNull() {
		if _, err := r.client.DeleteTelemetryConfig(ctx, apipb.DeleteTelemetryConfigRequest_builder{Tag: proto.String(data.Tag.ValueString())}.Build()); err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete telemetry config for tag %q: %v", data.Tag.ValueString(), err))
			return
		}
	}

	tflog.Info(ctx, "Deleted sync settings", map[string]any{"tag": data.Tag.ValueString()})
}

func (r *SyncSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Validate up front so we fail with a clear message instead of writing an
	// invalid tag into state and erroring later at Read time when the value is
	// interpolated into the ListSyncSettings filter.
	if l := len(req.ID); l < 1 || l > 42 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("tag %q must be between 1 and 42 characters, got %d", req.ID, l),
		)
		return
	}
	if !syncSettingsTagRegex.MatchString(req.ID) {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("tag %q must contain only letters, digits, periods, colons, hyphens, and underscores", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("tag"), req.ID)...)
}

func (r *SyncSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"tag": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

// replaceTagSettings deletes the tag's existing sync settings (if any) and
// upserts the settings derived from the plan. This guarantees that the
// server-side record exactly mirrors the Terraform configuration: fields
// unset in config end up unset on the server (lower-precedence tags apply),
// and fields set to empty values are sent as explicit empties.
//
// priorTelemetryEnabled is the telemetry_enabled value from the prior state
// (a null Bool on Create). It is used to decide whether a TelemetryConfig must
// be deleted, so that tenants not using telemetry are never forced to call the
// (feature-gated) telemetry RPCs.
func (r *SyncSettingsResource) replaceTagSettings(ctx context.Context, data *SyncSettingsResourceModel, priorTelemetryEnabled types.Bool, diags *diag.Diagnostics) bool {
	// Validate CEL fallback expressions server-side before the destructive
	// delete/update below, so an invalid expression fails without clearing the
	// tag's existing settings.
	r.validateCelFallbackRules(ctx, data.CelFallbackRule, diags)
	if diags.HasError() {
		return false
	}

	ss, d := syncSettingsModelToProto(ctx, data)
	diags.Append(d...)
	if diags.HasError() {
		return false
	}

	// DeleteSyncSettings is a no-op for tags with no record. For the special
	// "global" tag the server re-seeds defaults after delete, then the
	// subsequent UpdateSyncSettings merges our config on top. Document that
	// caveat in the resource description.
	delReq := apipb.DeleteSyncSettingsRequest_builder{Tag: proto.String(data.Tag.ValueString())}.Build()
	if _, err := r.client.DeleteSyncSettings(ctx, delReq); err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to clear existing sync settings for tag %q: %v", data.Tag.ValueString(), err))
		return false
	}

	upReq := apipb.UpdateSyncSettingsRequest_builder{SyncSettings: ss}.Build()
	if _, err := r.client.UpdateSyncSettings(ctx, upReq); err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to update sync settings for tag %q: %v", data.Tag.ValueString(), err))
		return false
	}

	return r.applyTelemetryConfig(ctx, data.Tag.ValueString(), data.TelemetryEnabled, priorTelemetryEnabled, diags)
}

// validateCelFallbackRules asks the server to validate each fallback rule's CEL
// expression. Expressions that are unknown (interpolated from another resource
// at plan time) or empty are skipped; the schema already requires a non-empty
// expression, so an empty value here can only be an unresolved reference.
func (r *SyncSettingsResource) validateCelFallbackRules(ctx context.Context, rules []SyncSettingsCelFallbackRuleModel, diags *diag.Diagnostics) {
	for i, rule := range rules {
		if rule.Expression.IsUnknown() || rule.Expression.ValueString() == "" {
			continue
		}
		if _, err := r.client.ValidateCELRule(ctx, apipb.ValidateCELRuleRequest_builder{
			Expression: proto.String(rule.Expression.ValueString()),
		}.Build()); err != nil {
			msg := err.Error()
			if st, ok := status.FromError(err); ok {
				msg = st.Message()
			}
			diags.AddAttributeError(
				path.Root("cel_fallback_rule").AtListIndex(i).AtName("expression"),
				"Invalid CEL expression",
				fmt.Sprintf("The CEL fallback expression failed validation: %s", msg),
			)
		}
	}
}

// applyTelemetryConfig reconciles the tag's TelemetryConfig with the plan.
// A set telemetry_enabled upserts the config; clearing it (null in plan when
// the prior state had a value) deletes it. When telemetry_enabled is and was
// unset, the telemetry RPCs are not called at all — important because they are
// gated behind a tenant feature flag and would otherwise error for tenants
// that do not use telemetry.
func (r *SyncSettingsResource) applyTelemetryConfig(ctx context.Context, tag string, planEnabled, priorEnabled types.Bool, diags *diag.Diagnostics) bool {
	switch {
	case !planEnabled.IsNull() && !planEnabled.IsUnknown():
		tc := apipb.TelemetryConfig_builder{
			Tag:     tag,
			Enabled: proto.Bool(planEnabled.ValueBool()),
		}.Build()
		if _, err := r.client.UpdateTelemetryConfig(ctx, apipb.UpdateTelemetryConfigRequest_builder{TelemetryConfig: tc}.Build()); err != nil {
			diags.AddError("Client Error", fmt.Sprintf("Failed to update telemetry config for tag %q: %v", tag, err))
			return false
		}
	case !priorEnabled.IsNull():
		// telemetry_enabled was previously set and is now removed: delete the
		// tag's TelemetryConfig so lower-precedence tags apply.
		if _, err := r.client.DeleteTelemetryConfig(ctx, apipb.DeleteTelemetryConfigRequest_builder{Tag: proto.String(tag)}.Build()); err != nil {
			diags.AddError("Client Error", fmt.Sprintf("Failed to delete telemetry config for tag %q: %v", tag, err))
			return false
		}
	}
	return true
}

// fetchTelemetryEnabled returns the tag's TelemetryConfig.enabled value, or a
// null Bool if there is no config. ListTelemetryConfigs is gated behind the
// tenant telemetry feature; if it is disabled the call fails, in which case we
// report null rather than failing the read (no config can exist anyway).
func (r *SyncSettingsResource) fetchTelemetryEnabled(ctx context.Context, tag string) types.Bool {
	filter := fmt.Sprintf(`tag = "%s"`, tag)
	ret, err := r.client.ListTelemetryConfigs(ctx, apipb.ListTelemetryConfigsRequest_builder{
		Filter:   proto.String(filter),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		tflog.Warn(ctx, "Failed to list telemetry configs; treating telemetry_enabled as unset", map[string]any{"tag": tag, "error": err.Error()})
		return types.BoolNull()
	}
	for _, tc := range ret.GetTelemetryConfigs() {
		if tc.GetTag() == tag {
			return boolPtrToTF(tc.Enabled)
		}
	}
	return types.BoolNull()
}

func (r *SyncSettingsResource) fetchSyncSettings(ctx context.Context, tag string) (*apipb.SyncSettings, bool, error) {
	filter := fmt.Sprintf(`tag = "%s"`, tag)
	ret, err := r.client.ListSyncSettings(ctx, apipb.ListSyncSettingsRequest_builder{
		Filter:   proto.String(filter),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		return nil, false, err
	}
	for _, ss := range ret.GetSyncSettings() {
		if ss.GetTag() == tag {
			return ss, true, nil
		}
	}
	return nil, false, nil
}

// syncSettingsModelToProto builds a SyncSettings proto from the Terraform
// model. Unset Terraform attributes become absent proto fields; explicit
// empty/zero values become present proto fields, preserving the
// unset-vs-empty distinction at the wire level.
func syncSettingsModelToProto(ctx context.Context, m *SyncSettingsResourceModel) (*apipb.SyncSettings, diag.Diagnostics) {
	var diags diag.Diagnostics

	b := apipb.SyncSettings_builder{
		Tag:                                     m.Tag.ValueString(),
		EnableTransitiveRules:                   tfBoolToPtr(m.EnableTransitiveRules),
		AllowedPathRegex:                        tfStringToPtr(m.AllowedPathRegex),
		BlockedPathRegex:                        tfStringToPtr(m.BlockedPathRegex),
		FullSyncIntervalSeconds:                 tfInt64ToUint32Ptr(m.FullSyncInterval),
		PushNotificationFullSyncIntervalSeconds: tfInt64ToUint32Ptr(m.PushSyncInterval),
	}

	if !m.ClientMode.IsNull() && !m.ClientMode.IsUnknown() {
		b.ClientMode = apipb.ClientMode(apipb.ClientMode_value[m.ClientMode.ValueString()])
	}

	if !m.NetworkExtensionEnabled.IsNull() && !m.NetworkExtensionEnabled.IsUnknown() {
		b.NetworkExtension = apipb.SyncSettings_NetworkExtension_builder{
			Enable: tfBoolToPtr(m.NetworkExtensionEnabled),
		}.Build()
	}

	if !m.TelemetryFilterExpressions.IsNull() && !m.TelemetryFilterExpressions.IsUnknown() {
		var values []string
		diags.Append(m.TelemetryFilterExpressions.ElementsAs(ctx, &values, false)...)
		if diags.HasError() {
			return nil, diags
		}
		if values == nil {
			values = []string{}
		}
		b.TelemetryFilterExpressions = apipb.RepeatedString_builder{Values: values}.Build()
	}

	if len(m.CelFallbackRule) > 0 {
		rules := make([]*apipb.SyncSettings_CELFallbackRule, len(m.CelFallbackRule))
		for i, r := range m.CelFallbackRule {
			rules[i] = apipb.SyncSettings_CELFallbackRule_builder{
				CelExpr:   r.Expression.ValueString(),
				CustomMsg: tfStringToPtr(r.CustomMsg),
				CustomUrl: tfStringToPtr(r.CustomURL),
			}.Build()
		}
		b.CelFallbackRules = apipb.SyncSettings_CELFallbackRules_builder{Rules: rules}.Build()
	}

	if m.OnDemandMonitorMode != nil {
		state := m.OnDemandMonitorMode.State.ValueString()
		odmmB := apipb.OnDemandMonitorMode_builder{
			State: apipb.OnDemandMonitorMode_OnDemandMonitorModeState(
				apipb.OnDemandMonitorMode_OnDemandMonitorModeState_value[state],
			),
		}
		if !m.OnDemandMonitorMode.MaxMinutes.IsNull() && !m.OnDemandMonitorMode.MaxMinutes.IsUnknown() {
			odmmB.MaxMinutes = uint32(m.OnDemandMonitorMode.MaxMinutes.ValueInt64())
		}
		if !m.OnDemandMonitorMode.DefaultDurationMinutes.IsNull() && !m.OnDemandMonitorMode.DefaultDurationMinutes.IsUnknown() {
			odmmB.DefaultDurationMinutes = uint32(m.OnDemandMonitorMode.DefaultDurationMinutes.ValueInt64())
		}
		b.OnDemandMonitorMode = odmmB.Build()
	}

	if m.NetworkMount != nil {
		nmB := apipb.SyncSettings_NetworkMount_builder{
			BannedMessage: tfStringToPtr(m.NetworkMount.BannedMessage),
		}
		if !m.NetworkMount.BlockMount.IsNull() && !m.NetworkMount.BlockMount.IsUnknown() {
			nmB.BlockMount = apipb.SyncSettings_NetworkMount_BlockMount(
				apipb.SyncSettings_NetworkMount_BlockMount_value[m.NetworkMount.BlockMount.ValueString()],
			)
		}
		if !m.NetworkMount.AllowedHosts.IsNull() && !m.NetworkMount.AllowedHosts.IsUnknown() {
			var hosts []string
			diags.Append(m.NetworkMount.AllowedHosts.ElementsAs(ctx, &hosts, false)...)
			if diags.HasError() {
				return nil, diags
			}
			if hosts == nil {
				hosts = []string{}
			}
			nmB.AllowedHosts = apipb.RepeatedString_builder{Values: hosts}.Build()
		}
		b.NetworkMount = nmB.Build()
	}

	if rm := removableMediaPolicyToProto(ctx, m.RemovableMediaPolicy, &diags); rm != nil {
		b.RemovableMediaPolicy = rm
	} else if diags.HasError() {
		return nil, diags
	}
	if rm := removableMediaPolicyToProto(ctx, m.EncryptedRemovableMediaPolicy, &diags); rm != nil {
		b.EncryptedRemovableMediaPolicy = rm
	} else if diags.HasError() {
		return nil, diags
	}

	return b.Build(), diags
}

func removableMediaPolicyToProto(ctx context.Context, m *SyncSettingsRemovableMediaPolicyModel, diags *diag.Diagnostics) *apipb.RemovableMediaPolicy {
	if m == nil {
		return nil
	}
	switch m.Action.ValueString() {
	case "ALLOW":
		return apipb.RemovableMediaPolicy_builder{Allow: proto.Bool(true)}.Build()
	case "BLOCK":
		return apipb.RemovableMediaPolicy_builder{Block: proto.Bool(true)}.Build()
	case "REMOUNT":
		var flags []string
		if !m.RemountFlags.IsNull() && !m.RemountFlags.IsUnknown() {
			diags.Append(m.RemountFlags.ElementsAs(ctx, &flags, false)...)
			if diags.HasError() {
				return nil
			}
		}
		return apipb.RemovableMediaPolicy_builder{
			Remount: apipb.RemountPolicy_builder{Flags: flags}.Build(),
		}.Build()
	default:
		// action unset: leave the wrapper unset (config validator already
		// caught nonsensical combinations).
		return nil
	}
}

// syncSettingsProtoToModel converts the server-returned SyncSettings into the
// Terraform model. Proto fields that are unset come back as null Terraform
// values, mirroring the round trip.
func syncSettingsProtoToModel(ctx context.Context, ss *apipb.SyncSettings) (SyncSettingsResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	m := SyncSettingsResourceModel{
		Tag:                   types.StringValue(ss.GetTag()),
		EnableTransitiveRules: boolPtrToTF(ss.EnableTransitiveRules),
		AllowedPathRegex:      stringPtrToTF(ss.AllowedPathRegex),
		BlockedPathRegex:      stringPtrToTF(ss.BlockedPathRegex),
		FullSyncInterval:      uint32PtrToTFInt64(ss.FullSyncIntervalSeconds),
		PushSyncInterval:      uint32PtrToTFInt64(ss.PushNotificationFullSyncIntervalSeconds),
		// telemetry_enabled is backed by the separate TelemetryConfig RPCs and
		// is populated by the caller (Read), not from SyncSettings.
		TelemetryEnabled: types.BoolNull(),
	}

	if ss.GetClientMode() != apipb.ClientMode_UNKNOWN_CLIENT_MODE {
		m.ClientMode = types.StringValue(ss.GetClientMode().String())
	} else {
		m.ClientMode = types.StringNull()
	}

	if ne := ss.GetNetworkExtension(); ne != nil && ne.HasEnable() {
		m.NetworkExtensionEnabled = boolPtrToTF(ne.Enable)
	} else {
		m.NetworkExtensionEnabled = types.BoolNull()
	}

	if ss.HasTelemetryFilterExpressions() {
		values := ss.GetTelemetryFilterExpressions().GetValues()
		if values == nil {
			values = []string{}
		}
		list, d := types.ListValueFrom(ctx, types.StringType, values)
		diags.Append(d...)
		if diags.HasError() {
			return m, diags
		}
		m.TelemetryFilterExpressions = list
	} else {
		m.TelemetryFilterExpressions = types.ListNull(types.StringType)
	}

	if ss.HasCelFallbackRules() {
		rules := ss.GetCelFallbackRules().GetRules()
		m.CelFallbackRule = make([]SyncSettingsCelFallbackRuleModel, len(rules))
		for i, r := range rules {
			m.CelFallbackRule[i] = SyncSettingsCelFallbackRuleModel{
				Expression: types.StringValue(r.GetCelExpr()),
				CustomMsg:  stringPtrToTF(r.CustomMsg),
				CustomURL:  stringPtrToTF(r.CustomUrl),
			}
		}
	}

	if odmm := ss.GetOnDemandMonitorMode(); odmm != nil {
		m.OnDemandMonitorMode = &SyncSettingsOnDemandMonitorModeModel{
			State:                  types.StringValue(odmm.GetState().String()),
			MaxMinutes:             zeroUint32ToNullInt64(odmm.GetMaxMinutes()),
			DefaultDurationMinutes: zeroUint32ToNullInt64(odmm.GetDefaultDurationMinutes()),
		}
	}

	if nm := ss.GetNetworkMount(); nm != nil {
		nmModel := &SyncSettingsNetworkMountModel{
			BannedMessage: stringPtrToTF(nm.BannedMessage),
		}
		if nm.GetBlockMount() != apipb.SyncSettings_NetworkMount_BLOCK_MOUNT_UNSPECIFIED {
			nmModel.BlockMount = types.StringValue(nm.GetBlockMount().String())
		} else {
			nmModel.BlockMount = types.StringNull()
		}
		if nm.HasAllowedHosts() {
			values := nm.GetAllowedHosts().GetValues()
			if values == nil {
				values = []string{}
			}
			list, d := types.ListValueFrom(ctx, types.StringType, values)
			diags.Append(d...)
			if diags.HasError() {
				return m, diags
			}
			nmModel.AllowedHosts = list
		} else {
			nmModel.AllowedHosts = types.ListNull(types.StringType)
		}
		m.NetworkMount = nmModel
	}

	if rm := removableMediaPolicyProtoToModel(ctx, ss.GetRemovableMediaPolicy(), &diags); rm != nil {
		m.RemovableMediaPolicy = rm
	}
	if diags.HasError() {
		return m, diags
	}
	if rm := removableMediaPolicyProtoToModel(ctx, ss.GetEncryptedRemovableMediaPolicy(), &diags); rm != nil {
		m.EncryptedRemovableMediaPolicy = rm
	}

	return m, diags
}

// zeroUint32ToNullInt64 treats a zero proto value as "unset" so that the
// optional Terraform attribute round-trips to null rather than 0.
func zeroUint32ToNullInt64(v uint32) types.Int64 {
	if v == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(int64(v))
}

func removableMediaPolicyProtoToModel(ctx context.Context, p *apipb.RemovableMediaPolicy, diags *diag.Diagnostics) *SyncSettingsRemovableMediaPolicyModel {
	if p == nil || !p.HasAction() {
		return nil
	}
	model := &SyncSettingsRemovableMediaPolicyModel{
		RemountFlags: types.ListNull(types.StringType),
	}
	switch {
	case p.HasAllow():
		model.Action = types.StringValue("ALLOW")
	case p.HasBlock():
		model.Action = types.StringValue("BLOCK")
	case p.HasRemount():
		model.Action = types.StringValue("REMOUNT")
		flags := p.GetRemount().GetFlags()
		if flags == nil {
			flags = []string{}
		}
		list, d := types.ListValueFrom(ctx, types.StringType, flags)
		diags.Append(d...)
		if diags.HasError() {
			return model
		}
		model.RemountFlags = list
	default:
		return nil
	}
	return model
}
