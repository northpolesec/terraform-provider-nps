// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &PackageRuleResource{}
var _ resource.ResourceWithConfigure = &PackageRuleResource{}
var _ resource.ResourceWithImportState = &PackageRuleResource{}

func NewPackageRuleResource() resource.Resource {
	return &PackageRuleResource{}
}

// PackageRuleResource defines the resource implementation.
type PackageRuleResource struct {
	client svcpb.WorkshopServiceClient
}

// PackageRuleResourceModel describes the resource data model.
type PackageRuleResourceModel struct {
	Tag           types.String `tfsdk:"tag"`
	Source        types.String `tfsdk:"source"`
	Name          types.String `tfsdk:"name"`
	Policy        types.String `tfsdk:"policy"`
	RuleType      types.String `tfsdk:"rule_type"`
	MinDate       types.String `tfsdk:"min_date"`
	MaxDate       types.String `tfsdk:"max_date"`
	VersionRegexp types.String `tfsdk:"version_regexp"`

	Id types.Int64 `tfsdk:"id"`
}

func (r *PackageRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_package_rule"
}

func (r *PackageRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_package_rule resource manages Package Rules. Package rules sync identifiers from GAL for a package. Management of package rules requires the read:rules and write:rules permissions.",
		MarkdownDescription: "The `nps_workshop_package_rule` resource manages Package Rules.\n\nPackage rules sync identifiers from GAL for a package.\n\nManagement of package rules requires the `read:rules` and `write:rules` permissions.",

		Attributes: map[string]schema.Attribute{
			"tag": schema.StringAttribute{
				Description:         "The tag for this package rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				MarkdownDescription: "The tag for this package rule. The tag determines which hosts this rule will apply to. The tag must already exist in Workshop.",
				Required:            true,
			},
			"source": schema.StringAttribute{
				Description:         "The package source (e.g., PACKAGE_SOURCE_HOMEBREW, PACKAGE_SOURCE_NPM).",
				MarkdownDescription: "The package source (e.g., `PACKAGE_SOURCE_HOMEBREW`, `PACKAGE_SOURCE_NPM`).",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(apipb.PackageSource(0).Descriptor())...),
				},
			},
			"name": schema.StringAttribute{
				Description:         "The package name (e.g., \"wget\", \"express\").",
				MarkdownDescription: "The package name (e.g., `wget`, `express`).",
				Required:            true,
			},
			"policy": schema.StringAttribute{
				Description:         "The policy for execution rules created from this package rule.",
				MarkdownDescription: "The policy for execution rules created from this package rule.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(apipb.Policy(0).Descriptor())...),
				},
			},
			"rule_type": schema.StringAttribute{
				Description:         "What type of rule should be created. Uses the broadest available type from GAL, falling back to more specific types if the preferred type isn't available. Only TEAMID, CERTIFICATE, SIGNINGID, CDHASH, and BINARY are supported.",
				MarkdownDescription: "What type of rule should be created. Uses the broadest available type from GAL, falling back to more specific types if the preferred type isn't available. Only `TEAMID`, `CERTIFICATE`, `SIGNINGID`, `CDHASH`, and `BINARY` are supported.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(apipb.RuleType(0).Descriptor())...),
				},
			},
			"min_date": schema.StringAttribute{
				Description:         "Optional: Only include versions released after this date. Format: RFC3339 (e.g., \"2024-01-01T00:00:00Z\").",
				MarkdownDescription: "Optional: Only include versions released after this date. Format: RFC3339 (e.g., `2024-01-01T00:00:00Z`).",
				Optional:            true,
			},
			"max_date": schema.StringAttribute{
				Description:         "Optional: Only include versions released before this date. Format: RFC3339 (e.g., \"2024-12-31T23:59:59Z\").",
				MarkdownDescription: "Optional: Only include versions released before this date. Format: RFC3339 (e.g., `2024-12-31T23:59:59Z`).",
				Optional:            true,
			},
			"version_regexp": schema.StringAttribute{
				Description:         "Optional: Regex to filter version strings.",
				MarkdownDescription: "Optional: Regex to filter version strings.",
				Optional:            true,
			},

			// Computed value, returned from Create
			"id": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "The automatically generated ID of this package rule",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *PackageRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *PackageRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PackageRuleResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Convert enum strings to enum values
	source := apipb.PackageSource_value[data.Source.ValueString()]
	policy := apipb.Policy_value[data.Policy.ValueString()]
	ruleType := apipb.RuleType_value[data.RuleType.ValueString()]

	// Build the package rule
	builder := apipb.PackageRule_builder{
		Tag:           data.Tag.ValueString(),
		Source:        apipb.PackageSource(source),
		Name:          data.Name.ValueString(),
		Policy:        apipb.Policy(policy),
		RuleType:      apipb.RuleType(ruleType),
		VersionRegexp: data.VersionRegexp.ValueString(),
	}

	// Parse and set optional timestamp fields
	if !data.MinDate.IsNull() && !data.MinDate.IsUnknown() {
		t, err := time.Parse(time.RFC3339, data.MinDate.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid min_date", fmt.Sprintf("Failed to parse min_date: %v", err))
			return
		}
		builder.MinDate = timestamppb.New(t)
	}

	if !data.MaxDate.IsNull() && !data.MaxDate.IsUnknown() {
		t, err := time.Parse(time.RFC3339, data.MaxDate.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid max_date", fmt.Sprintf("Failed to parse max_date: %v", err))
			return
		}
		builder.MaxDate = timestamppb.New(t)
	}

	crResp, err := r.client.CreatePackageRule(ctx, apipb.CreatePackageRuleRequest_builder{
		Rule: builder.Build(),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create package rule: %v", err))
		return
	}

	data.Id = types.Int64Value(crResp.GetRuleId())
	tflog.Info(ctx, fmt.Sprintf("Created package rule: %d", data.Id.ValueInt64()))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PackageRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PackageRuleResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Query for the rule by ID, or by (name, source, tag) combination
	filter := fmt.Sprintf(`rule_id = %d OR (name = "%s" AND source = "%s" AND tag = "%s")`,
		data.Id.ValueInt64(), data.Name.ValueString(), data.Source.ValueString(), data.Tag.ValueString())

	ret, err := r.client.ListPackageRules(ctx, apipb.ListPackageRulesRequest_builder{
		Filter:   proto.String(filter),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list package rules: %v", err))
		return
	}
	if len(ret.GetRules()) == 0 {
		// The rule was not found, remove it from the state so Terraform will offer
		// to create it.
		tflog.Info(ctx, fmt.Sprintf("Package rule %d not found", data.Id.ValueInt64()))
		resp.State.RemoveResource(ctx)
		return
	}

	// Now that we've found the rule, overwrite the state data with the actual
	// values retrieved via the API.
	rule := ret.GetRules()[0]
	data.Id = types.Int64Value(rule.GetRuleId())
	data.Tag = types.StringValue(rule.GetTag())
	data.Source = types.StringValue(rule.GetSource().String())
	data.Name = types.StringValue(rule.GetName())
	data.Policy = types.StringValue(rule.GetPolicy().String())
	data.RuleType = types.StringValue(rule.GetRuleType().String())

	if rule.GetVersionRegexp() != "" {
		data.VersionRegexp = types.StringValue(rule.GetVersionRegexp())
	}
	if rule.HasMinDate() {
		data.MinDate = types.StringValue(rule.GetMinDate().AsTime().Format(time.RFC3339))
	}
	if rule.HasMaxDate() {
		data.MaxDate = types.StringValue(rule.GetMaxDate().AsTime().Format(time.RFC3339))
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PackageRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Package rules don't support in-place updates. Users need to delete and recreate.
	resp.Diagnostics.AddError("Client Error", "nps_workshop_package_rule does not support in-place updates")
}

func (r *PackageRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PackageRuleResourceModel

	// Read Terraform prior state data into the model, which will give us the
	// rule ID to delete with.
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	ruleId := data.Id.ValueInt64()
	_, err := r.client.DeletePackageRule(ctx, apipb.DeletePackageRuleRequest_builder{
		RuleId: proto.Int64(ruleId),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete package rule: %v", err))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleted package rule: %d", ruleId))
}

func (r *PackageRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import a package rule by ID, which will trigger a Read.
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
