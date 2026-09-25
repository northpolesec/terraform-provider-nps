// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
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
var _ resource.Resource = &FileAccessRuleResource{}
var _ resource.ResourceWithConfigure = &FileAccessRuleResource{}
var _ resource.ResourceWithImportState = &FileAccessRuleResource{}
var _ resource.ResourceWithIdentity = &FileAccessRuleResource{}
var _ list.ListResource = &FileAccessRuleResource{}
var _ list.ListResourceWithConfigure = &FileAccessRuleResource{}

// fileAccessRuleTypePrefix is stripped from FileAccessRuleType values in HCL:
// the proto says FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES.
const fileAccessRuleTypePrefix = "FILE_ACCESS_RULE_TYPE_"

// fileAccessRuleTypeToFriendly maps each rule type to the CamelCase spelling
// this resource has always documented and writes back on read. The proto
// spellings (bare and prefixed) are accepted aliases; see
// fileAccessRuleTypeFromString.
var fileAccessRuleTypeToFriendly = map[apipb.FileAccessRuleType]string{
	apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES: "PathsWithAllowedProcesses",
	apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES:  "PathsWithDeniedProcesses",
	apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PROCESSES_WITH_ALLOWED_PATHS: "ProcessesWithAllowedPaths",
	apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PROCESSES_WITH_DENIED_PATHS:  "ProcessesWithDeniedPaths",
}

func fileAccessRuleTypeFriendlyName(rt apipb.FileAccessRuleType) string {
	if name, ok := fileAccessRuleTypeToFriendly[rt]; ok {
		return name
	}
	return rt.String()
}

// fileAccessRuleTypeAcceptedValues is the rule_type validator list: the
// CamelCase spellings this resource documents, plus both proto spellings of
// every value. Config generated from the raw API enum must plan cleanly.
func fileAccessRuleTypeAcceptedValues() []string {
	accepted := make([]string, 0, len(fileAccessRuleTypeToFriendly)*3)
	for _, friendly := range fileAccessRuleTypeToFriendly {
		accepted = append(accepted, friendly)
	}
	slices.Sort(accepted)
	return append(accepted, utils.ProtoEnumAcceptedValues(apipb.FileAccessRuleType(0).Descriptor(), fileAccessRuleTypePrefix)...)
}

// fileAccessRuleTypeFromString resolves any accepted spelling of a rule type.
// The second return is false for a value that names no rule type, which the
// validator rejects but an unvalidated path (an unmapped enum written back
// into state by an older provider) can still reach.
func fileAccessRuleTypeFromString(s string) (apipb.FileAccessRuleType, bool) {
	for rt, friendly := range fileAccessRuleTypeToFriendly {
		if s == friendly {
			return rt, true
		}
	}
	v, ok := apipb.FileAccessRuleType_value[utils.NormalizeEnum(s, fileAccessRuleTypePrefix)]
	if !ok || apipb.FileAccessRuleType(v) == apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_UNSPECIFIED {
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_UNSPECIFIED, false
	}
	return apipb.FileAccessRuleType(v), true
}

// fileAccessRuleTypeToModel maps a server rule type onto the model, keeping the
// spelling already in state when both name the same value so a refresh never
// rewrites state over spelling alone. An unrecognized value (the server
// returning UNSPECIFIED) leaves the prior value in place rather than writing a
// string the schema's own validator rejects.
func fileAccessRuleTypeToModel(prior types.String, rt apipb.FileAccessRuleType) types.String {
	if _, ok := fileAccessRuleTypeToFriendly[rt]; !ok {
		return prior
	}
	if got, ok := fileAccessRuleTypeFromString(prior.ValueString()); ok && got == rt {
		return prior
	}
	return types.StringValue(fileAccessRuleTypeFriendlyName(rt))
}

// fileAccessRuleTypeForm suppresses spelling-only diffs on rule_type: the
// CamelCase, bare proto, and prefixed proto spellings of a value are equal.
// enumForm cannot do this job because the CamelCase spelling is not a prefixed
// form of the proto name.
type fileAccessRuleTypeForm struct{}

func (m fileAccessRuleTypeForm) Description(context.Context) string {
	return "Treats the CamelCase and proto spellings of a rule type as equal."
}

func (m fileAccessRuleTypeForm) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m fileAccessRuleTypeForm) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.StateValue.IsNull() || req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	planned, okPlan := fileAccessRuleTypeFromString(req.PlanValue.ValueString())
	stated, okState := fileAccessRuleTypeFromString(req.StateValue.ValueString())
	if okPlan && okState && planned == stated {
		resp.PlanValue = req.StateValue
	}
}

// Prefixes stripped from the process override enums in HCL. Both spellings of
// each value are accepted.
const (
	fileAccessProcessTypePrefix   = "FILE_ACCESS_PROCESS_TYPE_"
	fileAccessProcessActionPrefix = "FILE_ACCESS_PROCESS_ACTION_"
)

// fileAccessProcessOverrideModel describes one process_overrides entry.
type fileAccessProcessOverrideModel struct {
	Type                types.String `tfsdk:"type"`
	Value               types.String `tfsdk:"value"`
	Action              types.String `tfsdk:"action"`
	AllowReadAccess     types.Bool   `tfsdk:"allow_read_access"`
	EnableSilentMode    types.Bool   `tfsdk:"enable_silent_mode"`
	EnableSilentTtyMode types.Bool   `tfsdk:"enable_silent_tty_mode"`
	BlockMessage        types.String `tfsdk:"block_message"`
	EventDetailUrl      types.String `tfsdk:"event_detail_url"`
	EventDetailText     types.String `tfsdk:"event_detail_text"`
}

var fileAccessProcessOverrideAttrTypes = map[string]attr.Type{
	"type":                   types.StringType,
	"value":                  types.StringType,
	"action":                 types.StringType,
	"allow_read_access":      types.BoolType,
	"enable_silent_mode":     types.BoolType,
	"enable_silent_tty_mode": types.BoolType,
	"block_message":          types.StringType,
	"event_detail_url":       types.StringType,
	"event_detail_text":      types.StringType,
}

var fileAccessProcessOverrideObjectType = types.ObjectType{AttrTypes: fileAccessProcessOverrideAttrTypes}

// fileAccessProcessOverridesToProto converts the process_overrides list to the
// proto form. Each unset optional field is left absent so the server inherits
// the rule's own value for it, which is what an omitted attribute means.
func fileAccessProcessOverridesToProto(ctx context.Context, l types.List, diags *diag.Diagnostics) []*apipb.FileAccessRule_ProcessOverride {
	if l.IsNull() || l.IsUnknown() {
		return nil
	}

	var ms []fileAccessProcessOverrideModel
	// Use a local diagnostics set so a caller that already accumulated an error
	// does not make this look like a conversion failure.
	var local diag.Diagnostics
	local.Append(l.ElementsAs(ctx, &ms, false)...)
	diags.Append(local...)
	if local.HasError() {
		return nil
	}

	out := make([]*apipb.FileAccessRule_ProcessOverride, 0, len(ms))
	for _, m := range ms {
		b := apipb.FileAccessRule_ProcessOverride_builder{
			Type:  apipb.FileAccessProcessType(apipb.FileAccessProcessType_value[utils.NormalizeEnum(m.Type.ValueString(), fileAccessProcessTypePrefix)]),
			Value: m.Value.ValueString(),
			// A null action is UNSPECIFIED: inherit the outcome the rule's
			// rule_type implies for this process.
			Action: apipb.FileAccessProcessAction(apipb.FileAccessProcessAction_value[utils.NormalizeEnum(m.Action.ValueString(), fileAccessProcessActionPrefix)]),
		}
		if !m.AllowReadAccess.IsNull() {
			b.AllowReadAccess = proto.Bool(m.AllowReadAccess.ValueBool())
		}
		if !m.EnableSilentMode.IsNull() {
			b.EnableSilentMode = proto.Bool(m.EnableSilentMode.ValueBool())
		}
		if !m.EnableSilentTtyMode.IsNull() {
			b.EnableSilentTtyMode = proto.Bool(m.EnableSilentTtyMode.ValueBool())
		}
		if !m.BlockMessage.IsNull() {
			b.BlockMessage = proto.String(m.BlockMessage.ValueString())
		}
		if !m.EventDetailUrl.IsNull() {
			b.EventDetailUrl = proto.String(m.EventDetailUrl.ValueString())
		}
		if !m.EventDetailText.IsNull() {
			b.EventDetailText = proto.String(m.EventDetailText.ValueString())
		}
		out = append(out, b.Build())
	}
	return out
}

// fileAccessProcessOverridesToModel converts the proto process overrides to the
// list attribute value, writing the canonical short enum spellings. A field the
// server reports as absent stays null, so it keeps reading as "inherit".
func fileAccessProcessOverridesToModel(ctx context.Context, overrides []*apipb.FileAccessRule_ProcessOverride, diags *diag.Diagnostics) types.List {
	if len(overrides) == 0 {
		return types.ListNull(fileAccessProcessOverrideObjectType)
	}

	ms := make([]fileAccessProcessOverrideModel, 0, len(overrides))
	for _, o := range overrides {
		m := fileAccessProcessOverrideModel{
			Type:  types.StringValue(utils.ShortEnum(o.GetType().String(), fileAccessProcessTypePrefix)),
			Value: types.StringValue(o.GetValue()),
		}
		if o.GetAction() != apipb.FileAccessProcessAction_FILE_ACCESS_PROCESS_ACTION_UNSPECIFIED {
			m.Action = types.StringValue(utils.ShortEnum(o.GetAction().String(), fileAccessProcessActionPrefix))
		}
		if o.HasAllowReadAccess() {
			m.AllowReadAccess = types.BoolValue(o.GetAllowReadAccess())
		}
		if o.HasEnableSilentMode() {
			m.EnableSilentMode = types.BoolValue(o.GetEnableSilentMode())
		}
		if o.HasEnableSilentTtyMode() {
			m.EnableSilentTtyMode = types.BoolValue(o.GetEnableSilentTtyMode())
		}
		if o.HasBlockMessage() {
			m.BlockMessage = types.StringValue(o.GetBlockMessage())
		}
		if o.HasEventDetailUrl() {
			m.EventDetailUrl = types.StringValue(o.GetEventDetailUrl())
		}
		if o.HasEventDetailText() {
			m.EventDetailText = types.StringValue(o.GetEventDetailText())
		}
		ms = append(ms, m)
	}

	l, d := types.ListValueFrom(ctx, fileAccessProcessOverrideObjectType, ms)
	diags.Append(d...)
	return l
}

func NewFileAccessRuleResource() resource.Resource {
	return &FileAccessRuleResource{}
}

// FileAccessRuleResource defines the resource implementation.
type FileAccessRuleResource struct {
	client svcpb.WorkshopServiceClient
}

// FileAccessRuleIdentityModel describes the identity data model.
type FileAccessRuleIdentityModel struct {
	Id types.Int64 `tfsdk:"id"`
}

// FileAccessRuleResourceModel describes the resource data model.
type FileAccessRuleResourceModel struct {
	Tag                       types.String `tfsdk:"tag"`
	Name                      types.String `tfsdk:"name"`
	AllowReadAccess           types.Bool   `tfsdk:"allow_read_access"`
	BlockViolations           types.Bool   `tfsdk:"block_violations"`
	RuleType                  types.String `tfsdk:"rule_type"`
	EnableSilentMode          types.Bool   `tfsdk:"enable_silent_mode"`
	EnableSilentTtyMode       types.Bool   `tfsdk:"enable_silent_tty_mode"`
	BlockMessage              types.String `tfsdk:"block_message"`
	EventDetailUrl            types.String `tfsdk:"event_detail_url"`
	EventDetailText           types.String `tfsdk:"event_detail_text"`
	PathLiterals              types.List   `tfsdk:"path_literals"`
	PathPrefixes              types.List   `tfsdk:"path_prefixes"`
	ProcessBinaryPaths        types.List   `tfsdk:"process_binary_paths"`
	ProcessCdHashes           types.List   `tfsdk:"process_cd_hashes"`
	ProcessSigningIds         types.List   `tfsdk:"process_signing_ids"`
	ProcessCertificateSha256s types.List   `tfsdk:"process_certificate_sha256s"`
	ProcessTeamIds            types.List   `tfsdk:"process_team_ids"`
	ProcessOverrides          types.List   `tfsdk:"process_overrides"`

	Id types.Int64 `tfsdk:"id"`
}

func (r *FileAccessRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_file_access_rule"
	// The rule ID (used as the identity) changes on every upsert, including
	// in-place updates, so the identity is mutable across the resource's life.
	resp.ResourceBehavior.MutableIdentity = true
}

func (r *FileAccessRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_file_access_rule resource manages file access rules. You need the read:rules and write:rules permissions. Changing paths, processes, or other non-key fields updates the existing rule. Changing name or tag replaces it. Terraform destroys the old rule first, so hosts have no rule until the new one is created. Set create_before_destroy if you're renaming the rule or moving it to another tag.",
		MarkdownDescription: "The `nps_workshop_file_access_rule` resource manages file access rules.\n\nYou need the `read:rules` and `write:rules` permissions.\n\nChanging paths, processes, or other non-key fields updates the existing rule. Changing `name` or `tag` replaces it. Terraform destroys the old rule first, so hosts have no rule until the new one is created. Set `create_before_destroy` if you're renaming the rule or moving it to another tag.",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description:         "The name for this file access rule. Rule names are unique per-tag.",
				MarkdownDescription: "The name for this file access rule. Rule names are unique per-tag.",
				Required:            true,
				Validators:          []validator.String{},
				// Part of the natural key (tag, name). The upsert only supersedes the
				// old rule when the key matches, so changing the key must replace
				// rather than update in place.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"tag": schema.StringAttribute{
				Description:         "The tag for this file access rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				MarkdownDescription: "The tag for this file access rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				Required:            true,
				// TODO(rah): Add validator
				// Part of the natural key; see name.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"allow_read_access": schema.BoolAttribute{
				Description:         "Whether to allow read access for files matching this rule.",
				MarkdownDescription: "Whether to allow read access for files matching this rule.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"block_violations": schema.BoolAttribute{
				Description:         "Whether to block violations of this file access rule.",
				MarkdownDescription: "Whether to block violations of this file access rule.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"rule_type": schema.StringAttribute{
				Description:         "The type of this file access rule. The possible values are: PathsWithAllowedProcesses, PathsWithDeniedProcesses, ProcessesWithAllowedPaths, ProcessesWithDeniedPaths. The proto spellings (PATHS_WITH_ALLOWED_PROCESSES and the FILE_ACCESS_RULE_TYPE_-prefixed form) are accepted aliases.",
				MarkdownDescription: "The type of this file access rule. The possible values are: `PathsWithAllowedProcesses`, `PathsWithDeniedProcesses`, `ProcessesWithAllowedPaths`, `ProcessesWithDeniedPaths`. The proto spellings (`PATHS_WITH_ALLOWED_PROCESSES` and the `FILE_ACCESS_RULE_TYPE_`-prefixed form) are accepted aliases.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(fileAccessRuleTypeAcceptedValues()...),
				},
				// Suppresses spelling-only diffs between the CamelCase and proto forms.
				PlanModifiers: []planmodifier.String{
					fileAccessRuleTypeForm{},
				},
			},
			"enable_silent_mode": schema.BoolAttribute{
				Description:         "Enable silent mode for this rule.",
				MarkdownDescription: "Enable silent mode for this rule.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"enable_silent_tty_mode": schema.BoolAttribute{
				Description:         "Enable silent TTY mode for this rule.",
				MarkdownDescription: "Enable silent TTY mode for this rule.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"block_message": schema.StringAttribute{
				Description:         "A custom message to display to the user when this rule blocks file access.",
				MarkdownDescription: "A custom message to display to the user when this rule blocks file access.",
				Optional:            true,
			},
			"event_detail_url": schema.StringAttribute{
				Description:         "A custom URL to redirect the user to when viewing details about a file access event. Setting a custom URL will override the EventDetailURL used by the Open button.",
				MarkdownDescription: "A custom URL to redirect the user to when viewing details about a file access event. Setting a custom URL will override the `EventDetailURL` used by the Open button.",
				Optional:            true,
			},
			"event_detail_text": schema.StringAttribute{
				Description:         "Custom text to display for the event detail link.",
				MarkdownDescription: "Custom text to display for the event detail link.",
				Optional:            true,
			},
			"path_literals": schema.ListAttribute{
				Description:         "Literal file paths that this rule applies to.",
				MarkdownDescription: "Literal file paths that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(0),
					listvalidator.AtLeastOneOf(path.MatchRoot("path_prefixes")),
				},
			},
			"path_prefixes": schema.ListAttribute{
				Description:         "Path prefixes that this rule applies to.",
				MarkdownDescription: "Path prefixes that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(0),
				},
			},
			"process_binary_paths": schema.ListAttribute{
				Description:         "Process binary paths that this rule applies to.",
				MarkdownDescription: "Process binary paths that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(0),
				},
			},
			"process_cd_hashes": schema.ListAttribute{
				Description:         "Process CDHashes that this rule applies to.",
				MarkdownDescription: "Process CDHashes that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(0),
					// TODO(rah): Add validator.
				},
			},
			"process_signing_ids": schema.ListAttribute{
				Description:         "Process signing IDs that this rule applies to.",
				MarkdownDescription: "Process signing IDs that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(0),
					// TODO(rah): Add validator.
				},
			},
			"process_certificate_sha256s": schema.ListAttribute{
				Description:         "Process certificate SHA256 hashes that this rule applies to.",
				MarkdownDescription: "Process certificate SHA256 hashes that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(0),
					// TODO(rah): Add validator.
				},
			},
			"process_team_ids": schema.ListAttribute{
				Description:         "Process team IDs that this rule applies to.",
				MarkdownDescription: "Process team IDs that this rule applies to.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(0),
					// TODO(rah): Add validator.
				},
			},
			"process_overrides": schema.ListNestedAttribute{
				Description:         "Per-process overrides of this rule's own settings, so that e.g. one process can be denied silently under a rule that otherwise allows the processes it lists. Each entry's type and value must match a process listed in the process_* attributes above; overrides referencing an unlisted process are rejected. Unset attributes within an entry inherit the rule's value. Omit the attribute rather than setting it to an empty list: the two mean the same thing to the server, which is a plain repeated field. Requires Santa 2026.8 or newer. Older agents ignore the overrides entirely and treat the process the way the rule treats one it does not list, which is a denial under PathsWithAllowedProcesses but an allow under PathsWithDeniedProcesses. Do not rely on a DENY override to block a process on an older agent under a PathsWithDeniedProcesses rule.",
				MarkdownDescription: "Per-process overrides of this rule's own settings, so that e.g. one process can be denied silently under a rule that otherwise allows the processes it lists.\n\nEach entry's `type` and `value` must match a process listed in the `process_*` attributes above; overrides referencing an unlisted process are rejected. Unset attributes within an entry inherit the rule's value.\n\nOmit the attribute rather than setting it to an empty list: the two mean the same thing to the server, which is a plain repeated field.\n\nRequires Santa 2026.8 or newer. Older agents ignore the overrides entirely and treat the process the way the rule treats one it does not list, which is a denial under `PathsWithAllowedProcesses` but an allow under `PathsWithDeniedProcesses`. Do not rely on a `DENY` override to block a process on an older agent under a `PathsWithDeniedProcesses` rule.",
				Optional:            true,
				Validators: []validator.List{
					// An empty list and an unset attribute mean the same thing on a
					// plain repeated field, and the server cannot report the
					// difference back, so only one of the two spellings can survive
					// a refresh. Reject the redundant one rather than let it diff on
					// every plan. (Contrast the sync settings attribute of the same
					// name, where a wrapper message makes an empty list meaningful.)
					listvalidator.SizeAtLeast(1),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Description:         "Which kind of process matcher this entry applies to. The possible values are: BINARY_PATH, CD_HASH, SIGNING_ID, CERTIFICATE_SHA256, and TEAM_ID. The FILE_ACCESS_PROCESS_TYPE_-prefixed spellings are accepted aliases.",
							MarkdownDescription: "Which kind of process matcher this entry applies to. The possible values are: `BINARY_PATH`, `CD_HASH`, `SIGNING_ID`, `CERTIFICATE_SHA256`, and `TEAM_ID`. The `FILE_ACCESS_PROCESS_TYPE_`-prefixed spellings are accepted aliases.",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf(utils.ProtoEnumAcceptedValues(apipb.FileAccessProcessType(0).Descriptor(), fileAccessProcessTypePrefix)...),
							},
							PlanModifiers: []planmodifier.String{
								enumForm(fileAccessProcessTypePrefix),
							},
						},
						"value": schema.StringAttribute{
							Description:         "The process matcher value, which must appear in the corresponding process_* attribute of the rule.",
							MarkdownDescription: "The process matcher value, which must appear in the corresponding `process_*` attribute of the rule.",
							Required:            true,
						},
						"action": schema.StringAttribute{
							Description:         "The action this rule takes for the process. The possible values are: ALLOW, AUDIT, and DENY. Leave unset to inherit the outcome the rule's rule_type implies. DENY does not by itself stop the process reading the files: an unset allow_read_access inherits the rule's value, so set allow_read_access to false as well to deny reads. The FILE_ACCESS_PROCESS_ACTION_-prefixed spellings are accepted aliases.",
							MarkdownDescription: "The action this rule takes for the process. The possible values are: `ALLOW`, `AUDIT`, and `DENY`. Leave unset to inherit the outcome the rule's `rule_type` implies.\n\n`DENY` does not by itself stop the process reading the files: an unset `allow_read_access` inherits the rule's value, so set `allow_read_access` to `false` as well to deny reads.\n\nThe `FILE_ACCESS_PROCESS_ACTION_`-prefixed spellings are accepted aliases.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.OneOf(utils.ProtoEnumAcceptedValues(apipb.FileAccessProcessAction(0).Descriptor(), fileAccessProcessActionPrefix)...),
							},
							PlanModifiers: []planmodifier.String{
								enumForm(fileAccessProcessActionPrefix),
							},
						},
						"allow_read_access": schema.BoolAttribute{
							Description:         "Overrides the rule's allow_read_access for this process. Unset inherits it.",
							MarkdownDescription: "Overrides the rule's `allow_read_access` for this process. Unset inherits it.",
							Optional:            true,
						},
						"enable_silent_mode": schema.BoolAttribute{
							Description:         "Overrides the rule's enable_silent_mode for this process. Unset inherits it.",
							MarkdownDescription: "Overrides the rule's `enable_silent_mode` for this process. Unset inherits it.",
							Optional:            true,
						},
						"enable_silent_tty_mode": schema.BoolAttribute{
							Description:         "Overrides the rule's enable_silent_tty_mode for this process. Unset inherits it.",
							MarkdownDescription: "Overrides the rule's `enable_silent_tty_mode` for this process. Unset inherits it.",
							Optional:            true,
						},
						"block_message": schema.StringAttribute{
							Description:         "Overrides the rule's block_message for this process. Unset inherits it.",
							MarkdownDescription: "Overrides the rule's `block_message` for this process. Unset inherits it.",
							Optional:            true,
						},
						"event_detail_url": schema.StringAttribute{
							Description:         "Overrides the rule's event_detail_url for this process. Unset inherits it.",
							MarkdownDescription: "Overrides the rule's `event_detail_url` for this process. Unset inherits it.",
							Optional:            true,
						},
						"event_detail_text": schema.StringAttribute{
							Description:         "Overrides the rule's event_detail_text for this process. Unset inherits it.",
							MarkdownDescription: "Overrides the rule's `event_detail_text` for this process. Unset inherits it.",
							Optional:            true,
						},
					},
				},
			},

			// Computed value, returned from Create. The ID changes on every
			// upsert (including in-place updates), so it is intentionally left
			// without UseStateForUnknown: it plans as "known after apply"
			// whenever the rule changes.
			"id": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "The server-generated ID of this file access rule. This ID is reassigned on every upsert, including in-place updates, so it must not be relied on as a stable identifier across applies.",
			},
		},
	}
}

func (r *FileAccessRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *FileAccessRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data FileAccessRuleResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	rule := buildFileAccessRule(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	crResp, err := r.client.CreateFileAccessRule(ctx, apipb.CreateFileAccessRuleRequest_builder{
		Rule: rule,
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create file access rule: %v", err))
		return
	}

	data.Id = types.Int64Value(crResp.GetRuleId())
	tflog.Info(ctx, fmt.Sprintf("Created file access rule: %d", data.Id.ValueInt64()))

	// Set the identity
	resp.Diagnostics.Append(resp.Identity.Set(ctx, FileAccessRuleIdentityModel{Id: data.Id})...)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FileAccessRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data FileAccessRuleResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Query for the rule by ID, name, and tag
	filter := fmt.Sprintf(`rule_id = %d OR (name = "%s" AND tag = "%s")`,
		data.Id.ValueInt64(), data.Name.ValueString(), data.Tag.ValueString())

	ret, err := r.client.ListFileAccessRules(ctx, apipb.ListFileAccessRulesRequest_builder{
		Filter:   proto.String(filter),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list file access rules: %v", err))
		return
	}
	if len(ret.GetRules()) == 0 {
		// The rule was not found, remove it from the state so Terraform will offer
		// to create it.
		tflog.Info(ctx, fmt.Sprintf("File access rule %d not found", data.Id.ValueInt64()))
		resp.State.RemoveResource(ctx)
		return
	}

	// Now that we've found the rule, overwrite the state data with the actual
	// values retrieved via the API.
	rule := ret.GetRules()[0]
	data.Id = types.Int64Value(rule.GetRuleId())
	data.Tag = types.StringValue(rule.GetTag())
	data.Name = types.StringValue(rule.GetName())
	data.AllowReadAccess = types.BoolValue(rule.GetAllowReadAccess())
	data.BlockViolations = types.BoolValue(rule.GetBlockViolations())
	data.RuleType = fileAccessRuleTypeToModel(data.RuleType, rule.GetRuleType())
	data.EnableSilentMode = types.BoolValue(rule.GetEnableSilentMode())
	data.EnableSilentTtyMode = types.BoolValue(rule.GetEnableSilentTtyMode())

	if rule.GetBlockMessage() != "" {
		data.BlockMessage = types.StringValue(rule.GetBlockMessage())
	}
	if rule.GetEventDetailUrl() != "" {
		data.EventDetailUrl = types.StringValue(rule.GetEventDetailUrl())
	}
	if rule.GetEventDetailText() != "" {
		data.EventDetailText = types.StringValue(rule.GetEventDetailText())
	}

	// Convert slices to list types
	if len(rule.GetPathLiterals()) > 0 {
		data.PathLiterals, _ = types.ListValueFrom(ctx, types.StringType, rule.GetPathLiterals())
	}
	if len(rule.GetPathPrefixes()) > 0 {
		data.PathPrefixes, _ = types.ListValueFrom(ctx, types.StringType, rule.GetPathPrefixes())
	}
	if len(rule.GetProcessBinaryPaths()) > 0 {
		data.ProcessBinaryPaths, _ = types.ListValueFrom(ctx, types.StringType, rule.GetProcessBinaryPaths())
	}
	if len(rule.GetProcessCdHashes()) > 0 {
		data.ProcessCdHashes, _ = types.ListValueFrom(ctx, types.StringType, rule.GetProcessCdHashes())
	}
	if len(rule.GetProcessSigningIds()) > 0 {
		data.ProcessSigningIds, _ = types.ListValueFrom(ctx, types.StringType, rule.GetProcessSigningIds())
	}
	if len(rule.GetProcessCertificateSha256S()) > 0 {
		data.ProcessCertificateSha256s, _ = types.ListValueFrom(ctx, types.StringType, rule.GetProcessCertificateSha256S())
	}
	if len(rule.GetProcessTeamIds()) > 0 {
		data.ProcessTeamIds, _ = types.ListValueFrom(ctx, types.StringType, rule.GetProcessTeamIds())
	}
	data.ProcessOverrides = fileAccessProcessOverridesToModel(ctx, rule.GetProcessOverrides(), &resp.Diagnostics)

	// Set the identity
	resp.Diagnostics.Append(resp.Identity.Set(ctx, FileAccessRuleIdentityModel{Id: data.Id})...)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// buildFileAccessRule builds the (upsert) FileAccessRule from the model.
func buildFileAccessRule(ctx context.Context, data FileAccessRuleResourceModel, diags *diag.Diagnostics) *apipb.FileAccessRule {
	ruleType, ok := fileAccessRuleTypeFromString(data.RuleType.ValueString())
	if !ok {
		diags.AddAttributeError(
			path.Root("rule_type"),
			"Unknown rule type",
			fmt.Sprintf("%q names no file access rule type.", data.RuleType.ValueString()),
		)
		return nil
	}

	builder := apipb.FileAccessRule_builder{
		Tag:                 data.Tag.ValueString(),
		Name:                data.Name.ValueString(),
		AllowReadAccess:     data.AllowReadAccess.ValueBool(),
		BlockViolations:     data.BlockViolations.ValueBool(),
		RuleType:            ruleType,
		EnableSilentMode:    data.EnableSilentMode.ValueBool(),
		EnableSilentTtyMode: data.EnableSilentTtyMode.ValueBool(),
		BlockMessage:        data.BlockMessage.ValueString(),
		EventDetailUrl:      data.EventDetailUrl.ValueString(),
		EventDetailText:     data.EventDetailText.ValueString(),
		ProcessOverrides:    fileAccessProcessOverridesToProto(ctx, data.ProcessOverrides, diags),
	}

	convertListHelper := func(v types.List, target *[]string) {
		if v.IsNull() || v.IsUnknown() {
			return
		}
		diags.Append(v.ElementsAs(ctx, target, false)...)
	}
	convertListHelper(data.PathLiterals, &builder.PathLiterals)
	convertListHelper(data.PathPrefixes, &builder.PathPrefixes)
	convertListHelper(data.ProcessBinaryPaths, &builder.ProcessBinaryPaths)
	convertListHelper(data.ProcessCdHashes, &builder.ProcessCdHashes)
	convertListHelper(data.ProcessSigningIds, &builder.ProcessSigningIds)
	convertListHelper(data.ProcessCertificateSha256s, &builder.ProcessCertificateSha256S)
	convertListHelper(data.ProcessTeamIds, &builder.ProcessTeamIds)

	return builder.Build()
}

func (r *FileAccessRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan FileAccessRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newID, diags := r.upsertFileAccessRule(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if newID.IsNull() {
		return
	}
	plan.Id = newID
	tflog.Info(ctx, fmt.Sprintf("Updated file access rule: %d", plan.Id.ValueInt64()))

	resp.Diagnostics.Append(resp.Identity.Set(ctx, FileAccessRuleIdentityModel{Id: plan.Id})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// upsertFileAccessRule performs an atomic update via the CreateFileAccessRule
// upsert RPC (keyed on (tag, name)) and returns the new rule ID. The server
// supersedes the existing rule sharing this key and returns a new ID, so the
// update is atomic and a failure leaves the old rule in place. The key
// attributes are RequiresReplace, so Update only ever changes non-key fields
// where the server is guaranteed to supersede; we never delete the old rule
// ourselves. Returns a null ID (with diagnostics) on failure.
func (r *FileAccessRuleResource) upsertFileAccessRule(ctx context.Context, plan FileAccessRuleResourceModel) (types.Int64, diag.Diagnostics) {
	var diags diag.Diagnostics

	rule := buildFileAccessRule(ctx, plan, &diags)
	if diags.HasError() {
		return types.Int64Null(), diags
	}

	crResp, err := r.client.CreateFileAccessRule(ctx, apipb.CreateFileAccessRuleRequest_builder{
		Rule: rule,
	}.Build())
	if err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to update file access rule: %v", err))
		return types.Int64Null(), diags
	}
	return types.Int64Value(crResp.GetRuleId()), diags
}

func (r *FileAccessRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data FileAccessRuleResourceModel

	// Read Terraform prior state data into the model, which will give us the
	// rule ID to delete with.
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	ruleId := data.Id.ValueInt64()
	_, err := r.client.DeleteFileAccessRule(ctx, apipb.DeleteFileAccessRuleRequest_builder{
		RuleId: proto.Int64(ruleId),
	}.Build())
	if err != nil && !isRuleDeleteNoOp(err) {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete file access rule: %v", err))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleted file access rule: %d", ruleId))
}

func (r *FileAccessRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import a file access rule by ID, which will trigger a Read.
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid ID", fmt.Sprintf("Failed to parse ID %q as integer: %v", req.ID, err))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func (r *FileAccessRuleResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.Int64Attribute{
				RequiredForImport: true,
			},
		},
	}
}

func NewFileAccessRuleListResource() list.ListResource {
	return &FileAccessRuleResource{}
}

func (r *FileAccessRuleResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "List all file access rules in the Workshop instance.",
		Attributes:  map[string]listschema.Attribute{},
	}
}

func (r *FileAccessRuleResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	stream.Results = func(push func(list.ListResult) bool) {
		rules, err := collectPages(func(page int) ([]*apipb.FileAccessRule, bool, error) {
			ret, err := r.client.ListFileAccessRules(ctx, apipb.ListFileAccessRulesRequest_builder{
				PageSize: proto.Uint32(uint32(listPageSize)),
				Page:     proto.Uint32(uint32(page)),
			}.Build())
			if err != nil {
				return nil, false, err
			}
			return ret.GetRules(), ret.GetMore(), nil
		}, func(rule *apipb.FileAccessRule) string {
			return strconv.FormatInt(rule.GetRuleId(), 10)
		})
		if err != nil {
			result := req.NewListResult(ctx)
			result.Diagnostics.AddError("Client Error", "Failed to list file access rules: "+err.Error())
			push(result)
			return
		}

		for _, rule := range rules {
			result := req.NewListResult(ctx)
			result.DisplayName = rule.GetName()

			result.Diagnostics.Append(result.Identity.Set(ctx, FileAccessRuleIdentityModel{
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

				model := FileAccessRuleResourceModel{
					Id:                        types.Int64Value(rule.GetRuleId()),
					Tag:                       types.StringValue(rule.GetTag()),
					Name:                      types.StringValue(rule.GetName()),
					AllowReadAccess:           types.BoolValue(rule.GetAllowReadAccess()),
					BlockViolations:           types.BoolValue(rule.GetBlockViolations()),
					RuleType:                  types.StringValue(fileAccessRuleTypeFriendlyName(rule.GetRuleType())),
					ProcessOverrides:          fileAccessProcessOverridesToModel(ctx, rule.GetProcessOverrides(), &result.Diagnostics),
					EnableSilentMode:          types.BoolValue(rule.GetEnableSilentMode()),
					EnableSilentTtyMode:       types.BoolValue(rule.GetEnableSilentTtyMode()),
					PathLiterals:              toListOrNull(rule.GetPathLiterals()),
					PathPrefixes:              toListOrNull(rule.GetPathPrefixes()),
					ProcessBinaryPaths:        toListOrNull(rule.GetProcessBinaryPaths()),
					ProcessCdHashes:           toListOrNull(rule.GetProcessCdHashes()),
					ProcessSigningIds:         toListOrNull(rule.GetProcessSigningIds()),
					ProcessCertificateSha256s: toListOrNull(rule.GetProcessCertificateSha256S()),
					ProcessTeamIds:            toListOrNull(rule.GetProcessTeamIds()),
				}

				if rule.GetBlockMessage() != "" {
					model.BlockMessage = types.StringValue(rule.GetBlockMessage())
				}
				if rule.GetEventDetailUrl() != "" {
					model.EventDetailUrl = types.StringValue(rule.GetEventDetailUrl())
				}
				if rule.GetEventDetailText() != "" {
					model.EventDetailText = types.StringValue(rule.GetEventDetailText())
				}

				result.Diagnostics.Append(result.Resource.Set(ctx, model)...)
			}

			if !push(result) {
				return
			}
		}
	}
}
