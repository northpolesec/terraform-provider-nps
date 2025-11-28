// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/protobuf/proto"

	syncpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &FileAccessRuleResource{}
var _ resource.ResourceWithConfigure = &FileAccessRuleResource{}
var _ resource.ResourceWithImportState = &FileAccessRuleResource{}

func NewFileAccessRuleResource() resource.Resource {
	return &FileAccessRuleResource{}
}

// FileAccessRuleResource defines the resource implementation.
type FileAccessRuleResource struct {
	client svcpb.WorkshopServiceClient
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

	Id types.Int64 `tfsdk:"id"`
}

func (r *FileAccessRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_file_access_rule"
}

func (r *FileAccessRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_file_access_rule resource manages File Access Rules. Management of file access rules requires the read:rules and write:rules permissions.",
		MarkdownDescription: "The `nps_workshop_file_access_rule` resource manages File Access Rules.\n\nManagement of file access rules requires the `read:rules` and `write:rules` permissions.",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description:         "The name for this file access rule. Rule names are unique per-tag.",
				MarkdownDescription: "The name for this file access rule. Rule names are unique per-tag.",
				Required:            true,
				Validators:          []validator.String{},
			},
			"tag": schema.StringAttribute{
				Description:         "The tag for this file access rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				MarkdownDescription: "The tag for this file access rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				Required:            true,
				// TODO(rah): Add validator
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
				Description:         "The type of this file access rule. The possible values are: PathsWithAllowedProcesses, PathsWithDeniedProcesses, ProcessesWithAllowedPaths, ProcessesWithDeniedPaths.",
				MarkdownDescription: "The type of this file access rule. The possible values are: `PathsWithAllowedProcesses`, `PathsWithDeniedProcesses`, `ProcessesWithAllowedPaths`, `ProcessesWithDeniedPaths`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"PathsWithAllowedProcesses",
						"PathsWithDeniedProcesses",
						"ProcessesWithAllowedPaths",
						"ProcessesWithDeniedPaths",
					),
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

			// Computed value, returned from Create
			"id": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "The automatically generated ID of this file access rule",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
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

	// Convert rule type string to enum
	ruleType := syncpb.FileAccessRule_RULE_TYPE_UNSPECIFIED
	switch data.RuleType.ValueString() {
	case "PathsWithAllowedProcesses":
		ruleType = syncpb.FileAccessRule_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES
	case "PathsWithDeniedProcesses":
		ruleType = syncpb.FileAccessRule_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES
	case "ProcessesWithAllowedPaths":
		ruleType = syncpb.FileAccessRule_RULE_TYPE_PROCESSES_WITH_ALLOWED_PATHS
	case "ProcessesWithDeniedPaths":
		ruleType = syncpb.FileAccessRule_RULE_TYPE_PROCESSES_WITH_DENIED_PATHS
	}

	// Build the file access rule
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
	}

	// Convert list attributes to string slices
	convertListHelper := func(v types.List, target *[]string) {
		if v.IsNull() || v.IsUnknown() {
			return
		}
		resp.Diagnostics.Append(v.ElementsAs(ctx, target, false)...)
	}
	convertListHelper(data.PathLiterals, &builder.PathLiterals)
	convertListHelper(data.PathPrefixes, &builder.PathPrefixes)
	convertListHelper(data.ProcessBinaryPaths, &builder.ProcessBinaryPaths)
	convertListHelper(data.ProcessCdHashes, &builder.ProcessCdHashes)
	convertListHelper(data.ProcessSigningIds, &builder.ProcessSigningIds)
	convertListHelper(data.ProcessCertificateSha256s, &builder.ProcessCertificateSha256S)
	convertListHelper(data.ProcessTeamIds, &builder.ProcessTeamIds)

	if resp.Diagnostics.HasError() {
		return
	}

	crResp, err := r.client.CreateFileAccessRule(ctx, apipb.CreateFileAccessRuleRequest_builder{
		Rule: builder.Build(),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create file access rule: %v", err))
		return
	}

	data.Id = types.Int64Value(crResp.GetRuleId())
	tflog.Info(ctx, fmt.Sprintf("Created file access rule: %d", data.Id.ValueInt64()))

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
	data.RuleType = types.StringValue(rule.GetRuleType().String())
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

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FileAccessRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// File access rules don't support in-place updates. Users need to delete and recreate.
	resp.Diagnostics.AddError("Client Error", "nps_workshop_file_access_rule does not support in-place updates")
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
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete file access rule: %v", err))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleted file access rule: %d", ruleId))
}

func (r *FileAccessRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import a file access rule by ID, which will trigger a Read.
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
