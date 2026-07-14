// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &WebhookSettingsResource{}
var _ resource.ResourceWithConfigure = &WebhookSettingsResource{}
var _ resource.ResourceWithImportState = &WebhookSettingsResource{}
var _ resource.ResourceWithIdentity = &WebhookSettingsResource{}

func NewWebhookSettingsResource() resource.Resource {
	return &WebhookSettingsResource{}
}

type WebhookSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type WebhookSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type WebhookSettingsResourceModel struct {
	AuditEvents       types.Object `tfsdk:"audit_events"`
	SignalReports     types.Object `tfsdk:"signal_reports"`
	SoftwareApprovals types.Object `tfsdk:"software_approvals"`
}

// The three source objects share the "basic" fields; each source adds its own
// event/state filter (software approvals has none).
type webhookAuditModel struct {
	Enabled         types.Bool   `tfsdk:"enabled"`
	Url             types.String `tfsdk:"url"`
	Secret          types.String `tfsdk:"secret"`
	SecretWo        types.String `tfsdk:"secret_wo"`
	SecretWoVersion types.String `tfsdk:"secret_wo_version"`
	Headers         types.List   `tfsdk:"headers"`
	Events          types.List   `tfsdk:"events"`
}

type webhookSignalModel struct {
	Enabled         types.Bool   `tfsdk:"enabled"`
	Url             types.String `tfsdk:"url"`
	Secret          types.String `tfsdk:"secret"`
	SecretWo        types.String `tfsdk:"secret_wo"`
	SecretWoVersion types.String `tfsdk:"secret_wo_version"`
	Headers         types.List   `tfsdk:"headers"`
	States          types.List   `tfsdk:"states"`
}

type webhookSoftwareModel struct {
	Enabled         types.Bool   `tfsdk:"enabled"`
	Url             types.String `tfsdk:"url"`
	Secret          types.String `tfsdk:"secret"`
	SecretWo        types.String `tfsdk:"secret_wo"`
	SecretWoVersion types.String `tfsdk:"secret_wo_version"`
	Headers         types.List   `tfsdk:"headers"`
}

type webhookHeaderModel struct {
	Key   types.String `tfsdk:"key"`
	Value types.String `tfsdk:"value"`
}

var webhookHeaderAttrTypes = map[string]attr.Type{
	"key":   types.StringType,
	"value": types.StringType,
}

var webhookHeadersListType = types.ListType{ElemType: types.ObjectType{AttrTypes: webhookHeaderAttrTypes}}

var webhookBasicAttrTypes = map[string]attr.Type{
	"enabled":           types.BoolType,
	"url":               types.StringType,
	"secret":            types.StringType,
	"secret_wo":         types.StringType,
	"secret_wo_version": types.StringType,
	"headers":           webhookHeadersListType,
}

func webhookObjectAttrTypes(extra map[string]attr.Type) map[string]attr.Type {
	m := map[string]attr.Type{}
	for k, v := range webhookBasicAttrTypes {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

var (
	webhookAuditAttrTypes    = webhookObjectAttrTypes(map[string]attr.Type{"events": types.ListType{ElemType: types.StringType}})
	webhookSignalAttrTypes   = webhookObjectAttrTypes(map[string]attr.Type{"states": types.ListType{ElemType: types.StringType}})
	webhookSoftwareAttrTypes = webhookObjectAttrTypes(nil)
)

func (r *WebhookSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_webhooks"
}

// webhookBasicAttributes returns the schema attributes common to every webhook
// source, merged with any source-specific attributes.
func webhookBasicAttributes(extra map[string]schema.Attribute) map[string]schema.Attribute {
	attrs := map[string]schema.Attribute{
		"enabled": schema.BoolAttribute{
			Description:         "Whether this webhook is enabled. A disabled webhook retains its URL and secret but delivers nothing.",
			MarkdownDescription: "Whether this webhook is enabled. A disabled webhook retains its URL and secret but delivers nothing.",
			Optional:            true,
		},
		"url": schema.StringAttribute{
			Description:         "Destination HTTPS URL. Empty disables the webhook.",
			MarkdownDescription: "Destination HTTPS URL. Empty disables the webhook.",
			Optional:            true,
		},
		"secret": schema.StringAttribute{
			Description:         "Signing secret keying the HMAC-SHA256 signature sent in the `webhook-signature` header. Write-only server-side (never returned by the API). Conflicts with secret_wo.",
			MarkdownDescription: "Signing secret keying the HMAC-SHA256 signature sent in the `webhook-signature` header. Write-only server-side (never returned by the API). Conflicts with `secret_wo`.",
			Optional:            true,
			Sensitive:           true,
		},
		"secret_wo": schema.StringAttribute{
			Description:         "Write-only variant of secret: its value is never stored in Terraform state. Supply from an ephemeral input. Conflicts with secret. Because write-only values are absent from state, changing this alone will not trigger an update — bump secret_wo_version to rotate it.",
			MarkdownDescription: "Write-only variant of `secret`: its value is never stored in Terraform state. Supply from an ephemeral input. Conflicts with `secret`. Because write-only values are absent from state, changing this alone will not trigger an update — bump `secret_wo_version` to rotate it.",
			Optional:            true,
			Sensitive:           true,
			WriteOnly:           true,
		},
		"secret_wo_version": schema.StringAttribute{
			Description:         "Trigger for rotating secret_wo. Since write-only values aren't stored in state, Terraform can't detect a changed secret_wo on its own; change this value whenever secret_wo changes to force the new secret to be sent.",
			MarkdownDescription: "Trigger for rotating `secret_wo`. Since write-only values aren't stored in state, Terraform can't detect a changed `secret_wo` on its own; change this value whenever `secret_wo` changes to force the new secret to be sent.",
			Optional:            true,
		},
		"headers": schema.ListNestedAttribute{
			Description:         "Additional HTTP headers attached to every delivery.",
			MarkdownDescription: "Additional HTTP headers attached to every delivery.",
			Optional:            true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"key":   schema.StringAttribute{Required: true},
					"value": schema.StringAttribute{Required: true, Sensitive: true},
				},
			},
		},
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return attrs
}

func (r *WebhookSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	desc := "The nps_workshop_settings_webhooks resource manages webhook settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource disables every configured webhook (their URLs and secrets are retained server-side, but no deliveries are made)."
	resp.Schema = schema.Schema{
		Description:         desc,
		MarkdownDescription: desc,
		Attributes: map[string]schema.Attribute{
			"audit_events": schema.SingleNestedAttribute{
				Description:         "Webhook fired on audit events.",
				MarkdownDescription: "Webhook fired on audit events.",
				Optional:            true,
				Attributes: webhookBasicAttributes(map[string]schema.Attribute{
					"events": schema.ListAttribute{
						Description:         "Audit event types to deliver (e.g. AUDIT_EVENT_RULE_UPSERT). Empty delivers all types.",
						MarkdownDescription: "Audit event types to deliver (e.g. `AUDIT_EVENT_RULE_UPSERT`). Empty delivers all types.",
						Optional:            true,
						ElementType:         types.StringType,
					},
				}),
			},
			"signal_reports": schema.SingleNestedAttribute{
				Description:         "Webhook fired on detection signal report receipt and state changes.",
				MarkdownDescription: "Webhook fired on detection signal report receipt and state changes.",
				Optional:            true,
				Attributes: webhookBasicAttributes(map[string]schema.Attribute{
					"states": schema.ListAttribute{
						Description:         "Signal report states to deliver on (e.g. SIGNAL_REPORT_STATE_NEW). Empty delivers all states.",
						MarkdownDescription: "Signal report states to deliver on (e.g. `SIGNAL_REPORT_STATE_NEW`). Empty delivers all states.",
						Optional:            true,
						ElementType:         types.StringType,
					},
				}),
			},
			"software_approvals": schema.SingleNestedAttribute{
				Description:         "Webhook fired the first time a piece of software is approved.",
				MarkdownDescription: "Webhook fired the first time a piece of software is approved.",
				Optional:            true,
				Attributes:          webhookBasicAttributes(nil),
			},
		},
	}
}

func (r *WebhookSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *WebhookSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.apply(ctx, req.Config, req.Plan, &resp.Diagnostics, &resp.State, resp.Identity)
	if !resp.Diagnostics.HasError() {
		tflog.Info(ctx, "Created webhook settings resource")
	}
}

func (r *WebhookSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.apply(ctx, req.Config, req.Plan, &resp.Diagnostics, &resp.State, resp.Identity)
	if !resp.Diagnostics.HasError() {
		tflog.Info(ctx, "Updated webhook settings resource")
	}
}

// apply is the shared Create/Update body; the two callers differ only in their
// request/response types, which resolve to the same tfsdk types below.
func (r *WebhookSettingsResource) apply(ctx context.Context, config tfsdk.Config, plan tfsdk.Plan, diags *diag.Diagnostics, state *tfsdk.State, identity *tfsdk.ResourceIdentity) {
	// The write-only secret_wo values live only in Config, so build the API
	// request from Config; persist Plan to state (where secret_wo is null).
	var cfg WebhookSettingsResourceModel
	diags.Append(config.Get(ctx, &cfg)...)
	if diags.HasError() {
		return
	}

	settings, d := webhookSettingsToProto(ctx, cfg)
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	upReq := apipb.UpdateWebhookSettingsRequest_builder{Settings: settings}.Build()
	if _, err := r.client.UpdateWebhookSettings(ctx, upReq); err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to update webhook settings: %v", err))
		return
	}

	var data WebhookSettingsResourceModel
	diags.Append(plan.Get(ctx, &data)...)
	if diags.HasError() {
		return
	}
	diags.Append(identity.Set(ctx, WebhookSettingsIdentityModel{Id: types.StringValue("webhook_settings")})...)
	diags.Append(state.Set(ctx, &data)...)
}

func (r *WebhookSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// The server never returns secrets, so carry them over from prior state to
	// avoid perpetual diffs on the (non-write-only) secret attribute.
	var prior WebhookSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ret, err := r.client.GetWebhookSettings(ctx, apipb.GetWebhookSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get webhook settings: %v", err))
		return
	}

	data, d := webhookProtoToModel(ctx, ret.GetSettings(), prior)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, WebhookSettingsIdentityModel{Id: types.StringValue("webhook_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *WebhookSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Disabling on destroy keeps each source's URL/secret server-side but stops
	// deliveries, matching the documented "enabled" semantics.
	var state WebhookSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings, d := webhookSettingsToProto(ctx, state)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, b := range []*apipb.WebhookBasicConfig{
		settings.GetAuditEvents().GetBasic(),
		settings.GetSignalReports().GetBasic(),
		settings.GetSoftwareApprovals().GetBasic(),
	} {
		if b != nil {
			b.SetEnabled(false)
		}
	}

	upReq := apipb.UpdateWebhookSettingsRequest_builder{Settings: settings}.Build()
	if _, err := r.client.UpdateWebhookSettings(ctx, upReq); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to disable webhook settings: %v", err))
		return
	}
	tflog.Info(ctx, "Disabled all configured webhooks")
}

func (r *WebhookSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &WebhookSettingsResourceModel{
		AuditEvents:       types.ObjectNull(webhookAuditAttrTypes),
		SignalReports:     types.ObjectNull(webhookSignalAttrTypes),
		SoftwareApprovals: types.ObjectNull(webhookSoftwareAttrTypes),
	})...)
}

func (r *WebhookSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{RequiredForImport: true},
		},
	}
}

// --- conversion helpers ---

func webhookSettingsToProto(ctx context.Context, m WebhookSettingsResourceModel) (*apipb.WebhookSettings, diag.Diagnostics) {
	var diags diag.Diagnostics
	b := apipb.WebhookSettings_builder{}

	if !m.AuditEvents.IsNull() && !m.AuditEvents.IsUnknown() {
		var s webhookAuditModel
		diags.Append(m.AuditEvents.As(ctx, &s, basetypes.ObjectAsOptions{})...)
		basic, d := webhookBasicToProto(ctx, s.Enabled, s.Url, s.Secret, s.SecretWo, s.Headers, path.Root("audit_events"))
		diags.Append(d...)
		events, d := auditEventsToProto(ctx, s.Events, path.Root("audit_events").AtName("events"))
		diags.Append(d...)
		b.AuditEvents = apipb.WebhookAuditEventConfig_builder{Basic: basic, Events: events}.Build()
	}
	if !m.SignalReports.IsNull() && !m.SignalReports.IsUnknown() {
		var s webhookSignalModel
		diags.Append(m.SignalReports.As(ctx, &s, basetypes.ObjectAsOptions{})...)
		basic, d := webhookBasicToProto(ctx, s.Enabled, s.Url, s.Secret, s.SecretWo, s.Headers, path.Root("signal_reports"))
		diags.Append(d...)
		states, d := signalStatesToProto(ctx, s.States, path.Root("signal_reports").AtName("states"))
		diags.Append(d...)
		b.SignalReports = apipb.WebhookSignalReportConfig_builder{Basic: basic, States: states}.Build()
	}
	if !m.SoftwareApprovals.IsNull() && !m.SoftwareApprovals.IsUnknown() {
		var s webhookSoftwareModel
		diags.Append(m.SoftwareApprovals.As(ctx, &s, basetypes.ObjectAsOptions{})...)
		basic, d := webhookBasicToProto(ctx, s.Enabled, s.Url, s.Secret, s.SecretWo, s.Headers, path.Root("software_approvals"))
		diags.Append(d...)
		b.SoftwareApprovals = apipb.WebhookSoftwareApprovalConfig_builder{Basic: basic}.Build()
	}

	return b.Build(), diags
}

func webhookBasicToProto(ctx context.Context, enabled types.Bool, url, secret, secretWo types.String, headers types.List, p path.Path) (*apipb.WebhookBasicConfig, diag.Diagnostics) {
	var diags diag.Diagnostics

	// secret and secret_wo are mutually exclusive; secret_wo wins if only it is set.
	sec := secret
	if !secretWo.IsNull() && !secretWo.IsUnknown() {
		if !secret.IsNull() && !secret.IsUnknown() {
			diags.AddAttributeError(p.AtName("secret_wo"), "Conflicting secret",
				"Set only one of secret or secret_wo for a webhook source.")
			return nil, diags
		}
		sec = secretWo
	}

	var hdrs []*apipb.HTTPHeader
	if !headers.IsNull() && !headers.IsUnknown() {
		var hms []webhookHeaderModel
		diags.Append(headers.ElementsAs(ctx, &hms, false)...)
		hdrs = make([]*apipb.HTTPHeader, len(hms))
		for i, hm := range hms {
			hdrs[i] = apipb.HTTPHeader_builder{Key: hm.Key.ValueString(), Value: hm.Value.ValueString()}.Build()
		}
	}

	return apipb.WebhookBasicConfig_builder{
		Enabled: tfBoolToPtr(enabled),
		Url:     tfStringToPtr(url),
		Secret:  tfStringToPtr(sec),
		Headers: hdrs,
	}.Build(), diags
}

func auditEventsToProto(ctx context.Context, l types.List, p path.Path) ([]apipb.AuditEvent, diag.Diagnostics) {
	var diags diag.Diagnostics
	if l.IsNull() || l.IsUnknown() {
		return nil, diags
	}
	var ss []string
	diags.Append(l.ElementsAs(ctx, &ss, false)...)
	out := make([]apipb.AuditEvent, len(ss))
	for i, s := range ss {
		v, ok := apipb.AuditEvent_value[s]
		if !ok {
			diags.AddAttributeError(p.AtListIndex(i), "Invalid audit event", fmt.Sprintf("%q is not a valid AuditEvent.", s))
			continue
		}
		out[i] = apipb.AuditEvent(v)
	}
	return out, diags
}

func signalStatesToProto(ctx context.Context, l types.List, p path.Path) ([]apipb.SignalReportState, diag.Diagnostics) {
	var diags diag.Diagnostics
	if l.IsNull() || l.IsUnknown() {
		return nil, diags
	}
	var ss []string
	diags.Append(l.ElementsAs(ctx, &ss, false)...)
	out := make([]apipb.SignalReportState, len(ss))
	for i, s := range ss {
		v, ok := apipb.SignalReportState_value[s]
		if !ok {
			diags.AddAttributeError(p.AtListIndex(i), "Invalid signal report state", fmt.Sprintf("%q is not a valid SignalReportState.", s))
			continue
		}
		out[i] = apipb.SignalReportState(v)
	}
	return out, diags
}

func webhookProtoToModel(ctx context.Context, s *apipb.WebhookSettings, prior WebhookSettingsResourceModel) (WebhookSettingsResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	out := WebhookSettingsResourceModel{
		AuditEvents:       types.ObjectNull(webhookAuditAttrTypes),
		SignalReports:     types.ObjectNull(webhookSignalAttrTypes),
		SoftwareApprovals: types.ObjectNull(webhookSoftwareAttrTypes),
	}
	if s == nil {
		return out, diags
	}

	if c := s.GetAuditEvents(); c != nil {
		vals, d := webhookBasicValues(ctx, c.GetBasic(), prior.AuditEvents)
		diags.Append(d...)
		events, d := enumsToTF(ctx, c.GetEvents(), priorList(prior.AuditEvents, "events"))
		diags.Append(d...)
		vals["events"] = events
		obj, d := types.ObjectValue(webhookAuditAttrTypes, vals)
		diags.Append(d...)
		out.AuditEvents = obj
	}
	if c := s.GetSignalReports(); c != nil {
		vals, d := webhookBasicValues(ctx, c.GetBasic(), prior.SignalReports)
		diags.Append(d...)
		states, d := enumsToTF(ctx, c.GetStates(), priorList(prior.SignalReports, "states"))
		diags.Append(d...)
		vals["states"] = states
		obj, d := types.ObjectValue(webhookSignalAttrTypes, vals)
		diags.Append(d...)
		out.SignalReports = obj
	}
	if c := s.GetSoftwareApprovals(); c != nil {
		vals, d := webhookBasicValues(ctx, c.GetBasic(), prior.SoftwareApprovals)
		diags.Append(d...)
		obj, d := types.ObjectValue(webhookSoftwareAttrTypes, vals)
		diags.Append(d...)
		out.SoftwareApprovals = obj
	}

	return out, diags
}

// priorString pulls a string attribute from a prior-state source object so Read
// can preserve values the server never returns (secret, secret_wo_version).
func priorString(obj types.Object, key string) types.String {
	if obj.IsNull() || obj.IsUnknown() {
		return types.StringNull()
	}
	if s, ok := obj.Attributes()[key].(types.String); ok {
		return s
	}
	return types.StringNull()
}

// priorList pulls a list attribute from a prior-state source object. Used to
// preserve the user's null-vs-empty choice for event/state filters, which the
// server flattens to "empty means all".
func priorList(obj types.Object, key string) types.List {
	if obj.IsNull() || obj.IsUnknown() {
		return types.ListNull(types.StringType)
	}
	if l, ok := obj.Attributes()[key].(types.List); ok {
		return l
	}
	return types.ListNull(types.StringType)
}

// priorHeaders pulls the headers list from a prior-state source object so Read
// preserves the user's null-vs-empty choice when the server returns none.
func priorHeaders(obj types.Object) types.List {
	if obj.IsNull() || obj.IsUnknown() {
		return types.ListNull(webhookHeaderAttrTypesObject())
	}
	if l, ok := obj.Attributes()["headers"].(types.List); ok {
		return l
	}
	return types.ListNull(webhookHeaderAttrTypesObject())
}

func webhookBasicValues(ctx context.Context, b *apipb.WebhookBasicConfig, prior types.Object) (map[string]attr.Value, diag.Diagnostics) {
	var diags diag.Diagnostics
	// Preserve the prior null-vs-empty choice when the server returns no headers,
	// mirroring how enumsToTF preserves the event/state filters.
	headers := priorHeaders(prior)
	if b != nil && len(b.GetHeaders()) > 0 {
		hms := make([]webhookHeaderModel, len(b.GetHeaders()))
		for i, h := range b.GetHeaders() {
			hms[i] = webhookHeaderModel{Key: types.StringValue(h.GetKey()), Value: types.StringValue(h.GetValue())}
		}
		l, d := types.ListValueFrom(ctx, webhookHeaderAttrTypesObject(), hms)
		diags.Append(d...)
		headers = l
	}
	return map[string]attr.Value{
		"enabled":           boolPtrToTF(basicEnabled(b)),
		"url":               stringPtrToTF(basicUrl(b)),
		"secret":            priorString(prior, "secret"),            // server never returns it
		"secret_wo":         types.StringNull(),                      // write-only: never in state
		"secret_wo_version": priorString(prior, "secret_wo_version"), // server doesn't track it
		"headers":           headers,
	}, diags
}

func webhookHeaderAttrTypesObject() attr.Type {
	return types.ObjectType{AttrTypes: webhookHeaderAttrTypes}
}

func basicEnabled(b *apipb.WebhookBasicConfig) *bool {
	if b == nil {
		return nil
	}
	return b.Enabled
}

func basicUrl(b *apipb.WebhookBasicConfig) *string {
	if b == nil {
		return nil
	}
	return b.Url
}

// enumsToTF renders a proto enum filter to a string list. The server flattens
// both null and [] to "empty means all", so when it returns nothing we preserve
// the prior-state representation to avoid a null-vs-empty round-trip diff.
func enumsToTF[E fmt.Stringer](ctx context.Context, evs []E, prior types.List) (types.List, diag.Diagnostics) {
	if len(evs) == 0 {
		return prior, nil
	}
	ss := make([]string, len(evs))
	for i, e := range evs {
		ss[i] = e.String()
	}
	return types.ListValueFrom(ctx, types.StringType, ss)
}
