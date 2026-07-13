// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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

	commonpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/common"
	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &SignalResource{}
var _ resource.ResourceWithConfigure = &SignalResource{}
var _ resource.ResourceWithValidateConfig = &SignalResource{}
var _ resource.ResourceWithImportState = &SignalResource{}
var _ resource.ResourceWithIdentity = &SignalResource{}
var _ list.ListResource = &SignalResource{}
var _ list.ListResourceWithConfigure = &SignalResource{}

func NewSignalResource() resource.Resource {
	return &SignalResource{}
}

func NewSignalListResource() list.ListResource {
	return &SignalResource{}
}

// SignalResource defines the resource implementation.
type SignalResource struct {
	client svcpb.WorkshopServiceClient
}

// SignalIdentityModel describes the identity data model. A signal is keyed by
// the (name, tag) pair.
type SignalIdentityModel struct {
	Name types.String `tfsdk:"name"`
	Tag  types.String `tfsdk:"tag"`
}

// SignalResourceModel describes the resource data model.
type SignalResourceModel struct {
	Name        types.String `tfsdk:"name"`
	Tag         types.String `tfsdk:"tag"`
	Description types.String `tfsdk:"description"`
	Severity    types.String `tfsdk:"severity"`
	Expression  types.String `tfsdk:"expression"`
	Disabled    types.Bool   `tfsdk:"disabled"`
	Labels      types.Set    `tfsdk:"labels"`
}

func (r *SignalResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_signal"
}

func (r *SignalResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_signal resource manages signals. A signal is a CEL expression evaluated against events on hosts carrying a given tag; a match produces a signal report. The (name, tag) pair is the primary key. Management of signals requires the read:rules and write:rules permissions. Changing name or tag forces replacement; add a create_before_destroy lifecycle block to avoid a window where the signal does not exist.",
		MarkdownDescription: "The `nps_workshop_signal` resource manages signals. A signal is a CEL expression evaluated against events on hosts carrying a given tag; a match produces a signal report. The `(name, tag)` pair is the primary key.\n\nManagement of signals requires the `read:rules` and `write:rules` permissions.\n\nUpdates to non-key fields are applied atomically in place. Changing the signal's natural key (`name` or `tag`) forces the signal to be replaced: by default Terraform destroys the old signal before creating the new one, leaving a brief window with no signal in place. To avoid that window, add a `create_before_destroy` lifecycle block:\n\n```hcl\nresource \"nps_workshop_signal\" \"example\" {\n  # ...\n  lifecycle {\n    create_before_destroy = true\n  }\n}\n```",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description:         "Stable identifier for the signal (e.g. \"CRED-001\"), echoed in reports. Unique per-tag.",
				MarkdownDescription: "Stable identifier for the signal (e.g. `CRED-001`), echoed in reports. Unique per-tag.",
				Required:            true,
				// Part of the natural key (name, tag). The upsert only supersedes the
				// old signal when the key matches, so changing the key must replace
				// rather than update in place.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"tag": schema.StringAttribute{
				Description:         "The tag this signal applies to. The tag determines which hosts this signal will apply to and must already exist in Workshop.",
				MarkdownDescription: "The tag this signal applies to. The tag determines which hosts this signal will apply to and must already exist in Workshop.",
				Required:            true,
				// Part of the natural key; see name.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description:         "A human-readable description of what this signal detects.",
				MarkdownDescription: "A human-readable description of what this signal detects.",
				Optional:            true,
			},
			"severity": schema.StringAttribute{
				Description:         "The severity assigned to reports produced by this signal.",
				MarkdownDescription: "The severity assigned to reports produced by this signal.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(utils.ProtoEnumToList(commonpb.Severity(0).Descriptor())...),
				},
			},
			"expression": schema.StringAttribute{
				Description:         "CEL boolean expression over `event`. A true result is a match.",
				MarkdownDescription: "CEL boolean expression over `event`. A true result is a match.",
				Required:            true,
			},
			"disabled": schema.BoolAttribute{
				Description:         "When true the signal is suppressed for hosts where this definition wins precedence (a higher-priority tag can disable a signal a lower tag enables).",
				MarkdownDescription: "When true the signal is suppressed for hosts where this definition wins precedence (a higher-priority tag can disable a signal a lower tag enables).",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"labels": schema.SetAttribute{
				Description:         "Free-form labels attached to the signal and copied onto each report it produces. Each label must be non-whitespace and at most 64 characters.",
				MarkdownDescription: "Free-form labels attached to the signal and copied onto each report it produces. Each label must be non-whitespace and at most 64 characters.",
				Optional:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (r *SignalResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SignalResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data SignalResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The client is nil during `terraform validate` (the provider isn't
	// configured), and the expression can be unknown when it's interpolated from
	// another resource. Skip the server round-trip in both cases.
	if r.client == nil || data.Expression.IsNull() || data.Expression.IsUnknown() {
		return
	}

	ret, err := r.client.ValidateSignal(ctx, apipb.ValidateSignalRequest_builder{
		Expression: proto.String(data.Expression.ValueString()),
	}.Build())
	if err != nil {
		// Don't fail the plan on a transient validation-RPC error; the upsert
		// will surface any real problem at apply time.
		tflog.Warn(ctx, fmt.Sprintf("Failed to validate signal expression: %v", err))
		return
	}
	if !ret.GetValid() {
		resp.Diagnostics.AddAttributeError(
			path.Root("expression"),
			"Invalid CEL expression",
			ret.GetError(),
		)
	}
}

// upsert builds and sends an UpsertSignal request from the model. It is shared
// by Create and Update, since the backend keys on (name, tag) and treats both
// the same way.
func (r *SignalResource) upsert(ctx context.Context, data SignalResourceModel) error {
	var labels []string
	if !data.Labels.IsNull() && !data.Labels.IsUnknown() {
		data.Labels.ElementsAs(ctx, &labels, false)
	}

	_, err := r.client.UpsertSignal(ctx, apipb.UpsertSignalRequest_builder{
		Signal: apipb.Signal_builder{
			Name:        data.Name.ValueString(),
			Tag:         data.Tag.ValueString(),
			Description: data.Description.ValueString(),
			Severity:    commonpb.Severity(commonpb.Severity_value[data.Severity.ValueString()]),
			Expression:  data.Expression.ValueString(),
			Disabled:    data.Disabled.ValueBool(),
			Labels:      labels,
		}.Build(),
	}.Build())
	return err
}

func (r *SignalResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SignalResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.upsert(ctx, data); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to create signal: %v", err))
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Created signal: %q (tag %q)", data.Name.ValueString(), data.Tag.ValueString()))

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SignalIdentityModel{Name: data.Name, Tag: data.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SignalResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SignalResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ret, err := r.client.ListSignals(ctx, apipb.ListSignalsRequest_builder{
		Filter:   proto.String(signalReadFilter(data.Name.ValueString(), data.Tag.ValueString())),
		PageSize: proto.Uint32(1),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list signals: %v", err))
		return
	}
	if len(ret.GetSignals()) == 0 {
		tflog.Info(ctx, fmt.Sprintf("Signal %q (tag %q) not found", data.Name.ValueString(), data.Tag.ValueString()))
		resp.State.RemoveResource(ctx)
		return
	}

	signal := ret.GetSignals()[0]
	data.Name = types.StringValue(signal.GetName())
	data.Tag = types.StringValue(signal.GetTag())
	data.Severity = types.StringValue(signal.GetSeverity().String())
	data.Expression = types.StringValue(signal.GetExpression())
	data.Disabled = types.BoolValue(signal.GetDisabled())
	data.Labels = stringSetOrNull(ctx, signal.GetLabels(), &resp.Diagnostics)
	if signal.GetDescription() != "" {
		data.Description = types.StringValue(signal.GetDescription())
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SignalIdentityModel{Name: data.Name, Tag: data.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update applies a change via the UpsertSignal RPC. The natural key (name, tag)
// is RequiresReplace, so Update only ever sees changes to non-key fields, where
// the server atomically supersedes the existing definition sharing the key. A
// failed upsert therefore leaves the old signal in place; we never delete it
// ourselves (key changes are handled by Terraform as a replace).
func (r *SignalResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SignalResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.upsert(ctx, plan); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update signal: %v", err))
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Updated signal: %q (tag %q)", plan.Name.ValueString(), plan.Tag.ValueString()))

	resp.Diagnostics.Append(resp.Identity.Set(ctx, SignalIdentityModel{Name: plan.Name, Tag: plan.Tag})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SignalResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data SignalResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteSignal(ctx, apipb.DeleteSignalRequest_builder{
		Name: proto.String(data.Name.ValueString()),
		Tag:  proto.String(data.Tag.ValueString()),
	}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete signal: %v", err))
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Deleted signal: %q (tag %q)", data.Name.ValueString(), data.Tag.ValueString()))
}

// signalReadFilter builds the ListSignals filter that selects the single
// signal identified by the (name, tag) primary key.
func signalReadFilter(name, tag string) string {
	return fmt.Sprintf(`name = %q AND tag = %q`, name, tag)
}

// parseSignalImportID splits a "tag/name" import ID into its components.
// Signals are keyed by (name, tag), so both halves must be non-empty.
func parseSignalImportID(id string) (tag, name string, err error) {
	tag, name, ok := strings.Cut(id, "/")
	if !ok || tag == "" || name == "" {
		return "", "", fmt.Errorf("expected import ID in the form \"tag/name\", got %q", id)
	}
	return tag, name, nil
}

func (r *SignalResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tag, name, err := parseSignalImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("tag"), tag)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

func (r *SignalResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"name": identityschema.StringAttribute{
				RequiredForImport: true,
			},
			"tag": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func (r *SignalResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "List all signals in the Workshop instance.",
		Attributes:  map[string]listschema.Attribute{},
	}
}

func (r *SignalResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	stream.Results = func(push func(list.ListResult) bool) {
		signals, err := collectPages(func(page int) ([]*apipb.Signal, bool, error) {
			ret, err := r.client.ListSignals(ctx, apipb.ListSignalsRequest_builder{
				PageSize: proto.Uint32(listPageSize),
				Page:     proto.Uint32(uint32(page)),
			}.Build())
			if err != nil {
				return nil, false, err
			}
			return ret.GetSignals(), ret.GetMore(), nil
		}, func(signal *apipb.Signal) string {
			return fmt.Sprintf("%d:%s%s", len(signal.GetTag()), signal.GetTag(), signal.GetName())
		})
		if err != nil {
			result := req.NewListResult(ctx)
			result.Diagnostics.AddError("Client Error", "Failed to list signals: "+err.Error())
			push(result)
			return
		}

		for _, signal := range signals {
			result := req.NewListResult(ctx)
			result.DisplayName = signal.GetName()

			result.Diagnostics.Append(result.Identity.Set(ctx, SignalIdentityModel{
				Name: types.StringValue(signal.GetName()),
				Tag:  types.StringValue(signal.GetTag()),
			})...)

			if req.IncludeResource {
				model := SignalResourceModel{
					Name:       types.StringValue(signal.GetName()),
					Tag:        types.StringValue(signal.GetTag()),
					Severity:   types.StringValue(signal.GetSeverity().String()),
					Expression: types.StringValue(signal.GetExpression()),
					Disabled:   types.BoolValue(signal.GetDisabled()),
					Labels:     stringSetOrNull(ctx, signal.GetLabels(), &result.Diagnostics),
				}
				if signal.GetDescription() != "" {
					model.Description = types.StringValue(signal.GetDescription())
				}
				result.Diagnostics.Append(result.Resource.Set(ctx, model)...)
			}

			if !push(result) {
				return
			}
		}
	}
}
