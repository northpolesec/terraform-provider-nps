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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &RiskEngineSettingsResource{}
var _ resource.ResourceWithConfigure = &RiskEngineSettingsResource{}
var _ resource.ResourceWithImportState = &RiskEngineSettingsResource{}
var _ resource.ResourceWithIdentity = &RiskEngineSettingsResource{}

func NewRiskEngineSettingsResource() resource.Resource {
	return &RiskEngineSettingsResource{}
}

type RiskEngineSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type RiskEngineSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type RiskEngineSettingsResourceModel struct {
	Enabled       types.Bool   `tfsdk:"enabled"`
	PluginTimeout types.String `tfsdk:"plugin_timeout"`
	LocalPlugins  types.Object `tfsdk:"local_plugins"`
	RemotePlugins types.List   `tfsdk:"remote_plugins"`
}

type riskLocalPluginsModel struct {
	VirusTotal     types.Object `tfsdk:"virus_total"`
	ReversingLabs  types.Object `tfsdk:"reversing_labs"`
	BlockableRules types.Object `tfsdk:"blockable_rules"`
}

type riskVirusTotalModel struct {
	Enabled         types.Bool   `tfsdk:"enabled"`
	ApiKey          types.String `tfsdk:"api_key"`
	CacheTtl        types.String `tfsdk:"cache_ttl"`
	NumCacheEntries types.Int64  `tfsdk:"num_cache_entries"`
	ExcludeEngines  types.List   `tfsdk:"exclude_engines"`
	FilterExpr      types.String `tfsdk:"filter_expr"`
}

type riskReversingLabsModel struct {
	Enabled         types.Bool   `tfsdk:"enabled"`
	Username        types.String `tfsdk:"username"`
	Password        types.String `tfsdk:"password"`
	CacheTtl        types.String `tfsdk:"cache_ttl"`
	NumCacheEntries types.Int64  `tfsdk:"num_cache_entries"`
	FilterExpr      types.String `tfsdk:"filter_expr"`
}

type riskBlockableRulesModel struct {
	Enabled    types.Bool   `tfsdk:"enabled"`
	Rules      types.List   `tfsdk:"rules"`
	FilterExpr types.String `tfsdk:"filter_expr"`
}

type riskBlockableRuleModel struct {
	Rule    types.String `tfsdk:"rule"`
	Comment types.String `tfsdk:"comment"`
	Uuid    types.String `tfsdk:"uuid"`
	Name    types.String `tfsdk:"name"`
}

type riskRemotePluginModel struct {
	Enabled    types.Bool   `tfsdk:"enabled"`
	Name       types.String `tfsdk:"name"`
	Version    types.String `tfsdk:"version"`
	Uuid       types.String `tfsdk:"uuid"`
	Url        types.String `tfsdk:"url"`
	Headers    types.List   `tfsdk:"headers"`
	Ttl        types.String `tfsdk:"ttl"`
	Secret     types.String `tfsdk:"secret"`
	FilterExpr types.String `tfsdk:"filter_expr"`
}

type riskHttpHeaderModel struct {
	Key   types.String `tfsdk:"key"`
	Value types.String `tfsdk:"value"`
}

var (
	riskVirusTotalAttrTypes = map[string]attr.Type{
		"enabled":           types.BoolType,
		"api_key":           types.StringType,
		"cache_ttl":         types.StringType,
		"num_cache_entries": types.Int64Type,
		"exclude_engines":   types.ListType{ElemType: types.StringType},
		"filter_expr":       types.StringType,
	}
	riskVirusTotalObjectType = types.ObjectType{AttrTypes: riskVirusTotalAttrTypes}

	riskReversingLabsAttrTypes = map[string]attr.Type{
		"enabled":           types.BoolType,
		"username":          types.StringType,
		"password":          types.StringType,
		"cache_ttl":         types.StringType,
		"num_cache_entries": types.Int64Type,
		"filter_expr":       types.StringType,
	}
	riskReversingLabsObjectType = types.ObjectType{AttrTypes: riskReversingLabsAttrTypes}

	riskBlockableRuleAttrTypes = map[string]attr.Type{
		"rule":    types.StringType,
		"comment": types.StringType,
		"uuid":    types.StringType,
		"name":    types.StringType,
	}
	riskBlockableRuleObjectType = types.ObjectType{AttrTypes: riskBlockableRuleAttrTypes}

	riskBlockableRulesAttrTypes = map[string]attr.Type{
		"enabled":     types.BoolType,
		"rules":       types.ListType{ElemType: riskBlockableRuleObjectType},
		"filter_expr": types.StringType,
	}
	riskBlockableRulesObjectType = types.ObjectType{AttrTypes: riskBlockableRulesAttrTypes}

	riskLocalPluginsAttrTypes = map[string]attr.Type{
		"virus_total":     riskVirusTotalObjectType,
		"reversing_labs":  riskReversingLabsObjectType,
		"blockable_rules": riskBlockableRulesObjectType,
	}
	riskLocalPluginsObjectType = types.ObjectType{AttrTypes: riskLocalPluginsAttrTypes}

	riskHttpHeaderAttrTypes = map[string]attr.Type{
		"key":   types.StringType,
		"value": types.StringType,
	}
	riskHttpHeaderObjectType = types.ObjectType{AttrTypes: riskHttpHeaderAttrTypes}

	riskRemotePluginAttrTypes = map[string]attr.Type{
		"enabled":     types.BoolType,
		"name":        types.StringType,
		"version":     types.StringType,
		"uuid":        types.StringType,
		"url":         types.StringType,
		"headers":     types.ListType{ElemType: riskHttpHeaderObjectType},
		"ttl":         types.StringType,
		"secret":      types.StringType,
		"filter_expr": types.StringType,
	}
	riskRemotePluginObjectType = types.ObjectType{AttrTypes: riskRemotePluginAttrTypes}
)

func (r *RiskEngineSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_risk_engine"
}

func (r *RiskEngineSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	headerNested := schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"key":   schema.StringAttribute{Required: true, MarkdownDescription: "HTTP header name."},
			"value": schema.StringAttribute{Required: true, Sensitive: true, MarkdownDescription: "HTTP header value."},
		},
	}

	blockableRuleNested := schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"rule":    schema.StringAttribute{Required: true, MarkdownDescription: "CEL expression body."},
			"comment": schema.StringAttribute{Optional: true, MarkdownDescription: "Free-form comment."},
			"uuid":    schema.StringAttribute{Optional: true, Computed: true, MarkdownDescription: "UUID assigned by the server. Leave unset when creating; provide the value from `GetRiskEngineSettings` to retain identity on update."},
			"name":    schema.StringAttribute{Optional: true, MarkdownDescription: "Rule name."},
		},
	}

	remotePluginNested := schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"enabled":     schema.BoolAttribute{Optional: true, MarkdownDescription: "Whether the plugin is enabled."},
			"name":        schema.StringAttribute{Optional: true, MarkdownDescription: "Plugin identifier."},
			"version":     schema.StringAttribute{Optional: true, MarkdownDescription: "Plugin version."},
			"uuid":        schema.StringAttribute{Optional: true, Computed: true, MarkdownDescription: "UUID for future updates."},
			"url":         schema.StringAttribute{Optional: true, MarkdownDescription: "URL of the plugin server."},
			"headers":     schema.ListNestedAttribute{Optional: true, NestedObject: headerNested, MarkdownDescription: "HTTP headers sent to the plugin server."},
			"ttl":         schema.StringAttribute{Optional: true, MarkdownDescription: "How long a response from the plugin server is valid (Go duration)."},
			"secret":      schema.StringAttribute{Optional: true, Sensitive: true, MarkdownDescription: "Hex-encoded shared secret for authenticating to the plugin."},
			"filter_expr": schema.StringAttribute{Optional: true, MarkdownDescription: "CEL expression evaluated before invoking the plugin. Empty = always run."},
		},
	}

	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_risk_engine resource manages risk engine settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",
		MarkdownDescription: "The `nps_workshop_settings_risk_engine` resource manages risk engine settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",

		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether the risk engine is enabled.",
			},
			"plugin_timeout": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "How long to wait for all plugins to respond (Go duration string, e.g. `\"5s\"`).",
			},
			"local_plugins": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Settings for plugins embedded in Workshop.",
				Attributes: map[string]schema.Attribute{
					"virus_total": schema.SingleNestedAttribute{
						Optional:            true,
						MarkdownDescription: "VirusTotal plugin settings.",
						Attributes: map[string]schema.Attribute{
							"enabled":           schema.BoolAttribute{Optional: true},
							"api_key":           schema.StringAttribute{Optional: true, Sensitive: true},
							"cache_ttl":         schema.StringAttribute{Optional: true, MarkdownDescription: "Cache TTL as a Go duration."},
							"num_cache_entries": schema.Int64Attribute{Optional: true, MarkdownDescription: "Number of cache entries (0-50,000)."},
							"exclude_engines":   schema.ListAttribute{Optional: true, ElementType: types.StringType, MarkdownDescription: "Engines to exclude from VirusTotal responses."},
							"filter_expr":       schema.StringAttribute{Optional: true, MarkdownDescription: "CEL expression evaluated before invoking the plugin."},
						},
					},
					"reversing_labs": schema.SingleNestedAttribute{
						Optional:            true,
						MarkdownDescription: "ReversingLabs plugin settings.",
						Attributes: map[string]schema.Attribute{
							"enabled":           schema.BoolAttribute{Optional: true},
							"username":          schema.StringAttribute{Optional: true},
							"password":          schema.StringAttribute{Optional: true, Sensitive: true},
							"cache_ttl":         schema.StringAttribute{Optional: true, MarkdownDescription: "Cache TTL as a Go duration."},
							"num_cache_entries": schema.Int64Attribute{Optional: true, MarkdownDescription: "Number of cache entries (0-50,000)."},
							"filter_expr":       schema.StringAttribute{Optional: true},
						},
					},
					"blockable_rules": schema.SingleNestedAttribute{
						Optional:            true,
						MarkdownDescription: "Built-in BlockableRule plugin settings.",
						Attributes: map[string]schema.Attribute{
							"enabled":     schema.BoolAttribute{Optional: true},
							"rules":       schema.ListNestedAttribute{Optional: true, NestedObject: blockableRuleNested, MarkdownDescription: "Rules for the BlockableRule plugin."},
							"filter_expr": schema.StringAttribute{Optional: true},
						},
					},
				},
			},
			"remote_plugins": schema.ListNestedAttribute{
				Optional:            true,
				NestedObject:        remotePluginNested,
				MarkdownDescription: "Remote (webhook-based) risk engine plugins.",
			},
		},
	}
}

func (r *RiskEngineSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *RiskEngineSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RiskEngineSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings, d := riskEngineModelToProto(ctx, &data)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := r.client.UpdateRiskEngineSettings(ctx, apipb.UpdateRiskEngineSettingsRequest_builder{RiskEngineSettings: settings}.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update risk engine settings: %v", err))
		return
	}

	tflog.Info(ctx, "Created risk engine settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, RiskEngineSettingsIdentityModel{Id: types.StringValue("risk_engine_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RiskEngineSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetRiskEngineSettings(ctx, apipb.GetRiskEngineSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get risk engine settings: %v", err))
		return
	}

	data, d := riskEngineProtoToModel(ctx, ret.GetRiskEngineSettings())
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, RiskEngineSettingsIdentityModel{Id: types.StringValue("risk_engine_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RiskEngineSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan RiskEngineSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// UpdateRiskEngineSettings replaces the whole RiskEngineSettings message;
	// it is not presence-sensitive, so we always send the full plan.
	settings, d := riskEngineModelToProto(ctx, &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := r.client.UpdateRiskEngineSettings(ctx, apipb.UpdateRiskEngineSettingsRequest_builder{RiskEngineSettings: settings}.Build()); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update risk engine settings: %v", err))
		return
	}

	tflog.Info(ctx, "Updated risk engine settings")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, RiskEngineSettingsIdentityModel{Id: types.StringValue("risk_engine_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RiskEngineSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed risk engine settings from Terraform state (server-side configuration unchanged)")
}

func (r *RiskEngineSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &RiskEngineSettingsResourceModel{
		LocalPlugins:  types.ObjectNull(riskLocalPluginsAttrTypes),
		RemotePlugins: types.ListNull(riskRemotePluginObjectType),
	})...)
}

func (r *RiskEngineSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

// --- proto/model conversion ---

func riskEngineProtoToModel(ctx context.Context, s *apipb.RiskEngineSettings) (RiskEngineSettingsResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	if s == nil {
		return RiskEngineSettingsResourceModel{
			LocalPlugins:  types.ObjectNull(riskLocalPluginsAttrTypes),
			RemotePlugins: types.ListNull(riskRemotePluginObjectType),
		}, nil
	}

	local, d := riskLocalPluginsProtoToObject(ctx, s.GetLocalPlugins())
	diags.Append(d...)

	remote, d := riskRemotePluginsProtoToList(ctx, s.GetRemotePlugins())
	diags.Append(d...)

	return RiskEngineSettingsResourceModel{
		Enabled:       boolPtrToTF(s.Enabled),
		PluginTimeout: durationToTFString(s.GetPluginTimeout()),
		LocalPlugins:  local,
		RemotePlugins: remote,
	}, diags
}

func riskEngineModelToProto(ctx context.Context, m *RiskEngineSettingsResourceModel) (*apipb.RiskEngineSettings, diag.Diagnostics) {
	var diags diag.Diagnostics

	pluginTimeout, err := tfStringToDuration(m.PluginTimeout)
	if err != nil {
		diags.AddAttributeError(path.Root("plugin_timeout"), "Invalid duration", err.Error())
		return nil, diags
	}

	local, d := riskLocalPluginsObjectToProto(ctx, m.LocalPlugins)
	diags.Append(d...)

	remote, d := riskRemotePluginsListToProto(ctx, m.RemotePlugins)
	diags.Append(d...)

	if diags.HasError() {
		return nil, diags
	}

	return apipb.RiskEngineSettings_builder{
		Enabled:       tfBoolToPtr(m.Enabled),
		PluginTimeout: pluginTimeout,
		LocalPlugins:  local,
		RemotePlugins: remote,
	}.Build(), diags
}

func riskLocalPluginsProtoToObject(ctx context.Context, lp *apipb.LocalPluginSettings) (types.Object, diag.Diagnostics) {
	if lp == nil {
		return types.ObjectNull(riskLocalPluginsAttrTypes), nil
	}
	var diags diag.Diagnostics

	vt, d := riskVirusTotalProtoToObject(ctx, lp.GetVirusTotal())
	diags.Append(d...)
	rl, d := riskReversingLabsProtoToObject(ctx, lp.GetReversingLabs())
	diags.Append(d...)
	br, d := riskBlockableRulesProtoToObject(ctx, lp.GetBlockableRules())
	diags.Append(d...)
	if diags.HasError() {
		return types.ObjectNull(riskLocalPluginsAttrTypes), diags
	}

	obj, d := types.ObjectValue(riskLocalPluginsAttrTypes, map[string]attr.Value{
		"virus_total":     vt,
		"reversing_labs":  rl,
		"blockable_rules": br,
	})
	diags.Append(d...)
	return obj, diags
}

func riskLocalPluginsObjectToProto(ctx context.Context, obj types.Object) (*apipb.LocalPluginSettings, diag.Diagnostics) {
	if obj.IsNull() || obj.IsUnknown() {
		return nil, nil
	}
	var m riskLocalPluginsModel
	d := obj.As(ctx, &m, basetypes.ObjectAsOptions{})
	if d.HasError() {
		return nil, d
	}

	var diags diag.Diagnostics
	vt, d := riskVirusTotalObjectToProto(ctx, m.VirusTotal)
	diags.Append(d...)
	rl, d := riskReversingLabsObjectToProto(ctx, m.ReversingLabs)
	diags.Append(d...)
	br, d := riskBlockableRulesObjectToProto(ctx, m.BlockableRules)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	return apipb.LocalPluginSettings_builder{
		VirusTotal:     vt,
		ReversingLabs:  rl,
		BlockableRules: br,
	}.Build(), diags
}

func riskVirusTotalProtoToObject(ctx context.Context, p *apipb.VirusTotalPluginSettings) (types.Object, diag.Diagnostics) {
	if p == nil {
		return types.ObjectNull(riskVirusTotalAttrTypes), nil
	}
	excludeEngines, diags := types.ListValueFrom(ctx, types.StringType, p.GetExcludeEngines())
	if diags.HasError() {
		return types.ObjectNull(riskVirusTotalAttrTypes), diags
	}
	if len(p.GetExcludeEngines()) == 0 {
		excludeEngines = types.ListNull(types.StringType)
	}
	obj, d := types.ObjectValue(riskVirusTotalAttrTypes, map[string]attr.Value{
		"enabled":           boolPtrToTF(p.Enabled),
		"api_key":           stringPtrToTF(p.ApiKey),
		"cache_ttl":         durationToTFString(p.GetCacheTtl()),
		"num_cache_entries": uint32PtrToTFInt64(p.NumCacheEntries),
		"exclude_engines":   excludeEngines,
		"filter_expr":       emptyStringToNull(p.GetFilterExpr()),
	})
	diags.Append(d...)
	return obj, diags
}

func riskVirusTotalObjectToProto(ctx context.Context, obj types.Object) (*apipb.VirusTotalPluginSettings, diag.Diagnostics) {
	if obj.IsNull() || obj.IsUnknown() {
		return nil, nil
	}
	var m riskVirusTotalModel
	d := obj.As(ctx, &m, basetypes.ObjectAsOptions{})
	if d.HasError() {
		return nil, d
	}

	cacheTtl, err := tfStringToDuration(m.CacheTtl)
	if err != nil {
		d.AddAttributeError(path.Root("local_plugins").AtName("virus_total").AtName("cache_ttl"), "Invalid duration", err.Error())
		return nil, d
	}

	var engines []string
	if !m.ExcludeEngines.IsNull() && !m.ExcludeEngines.IsUnknown() {
		d.Append(m.ExcludeEngines.ElementsAs(ctx, &engines, false)...)
		if d.HasError() {
			return nil, d
		}
	}

	return apipb.VirusTotalPluginSettings_builder{
		Enabled:         tfBoolToPtr(m.Enabled),
		ApiKey:          tfStringToPtr(m.ApiKey),
		CacheTtl:        cacheTtl,
		NumCacheEntries: tfInt64ToUint32Ptr(m.NumCacheEntries),
		ExcludeEngines:  engines,
		FilterExpr:      m.FilterExpr.ValueString(),
	}.Build(), d
}

func riskReversingLabsProtoToObject(ctx context.Context, p *apipb.ReversingLabsPluginSettings) (types.Object, diag.Diagnostics) {
	if p == nil {
		return types.ObjectNull(riskReversingLabsAttrTypes), nil
	}
	obj, diags := types.ObjectValue(riskReversingLabsAttrTypes, map[string]attr.Value{
		"enabled":           boolPtrToTF(p.Enabled),
		"username":          stringPtrToTF(p.Username),
		"password":          stringPtrToTF(p.Password),
		"cache_ttl":         durationToTFString(p.GetCacheTtl()),
		"num_cache_entries": uint32PtrToTFInt64(p.NumCacheEntries),
		"filter_expr":       emptyStringToNull(p.GetFilterExpr()),
	})
	return obj, diags
}

func riskReversingLabsObjectToProto(ctx context.Context, obj types.Object) (*apipb.ReversingLabsPluginSettings, diag.Diagnostics) {
	if obj.IsNull() || obj.IsUnknown() {
		return nil, nil
	}
	var m riskReversingLabsModel
	d := obj.As(ctx, &m, basetypes.ObjectAsOptions{})
	if d.HasError() {
		return nil, d
	}

	cacheTtl, err := tfStringToDuration(m.CacheTtl)
	if err != nil {
		d.AddAttributeError(path.Root("local_plugins").AtName("reversing_labs").AtName("cache_ttl"), "Invalid duration", err.Error())
		return nil, d
	}

	return apipb.ReversingLabsPluginSettings_builder{
		Enabled:         tfBoolToPtr(m.Enabled),
		Username:        tfStringToPtr(m.Username),
		Password:        tfStringToPtr(m.Password),
		CacheTtl:        cacheTtl,
		NumCacheEntries: tfInt64ToUint32Ptr(m.NumCacheEntries),
		FilterExpr:      m.FilterExpr.ValueString(),
	}.Build(), d
}

func riskBlockableRulesProtoToObject(ctx context.Context, p *apipb.BlockableRulePluginSettings) (types.Object, diag.Diagnostics) {
	if p == nil {
		return types.ObjectNull(riskBlockableRulesAttrTypes), nil
	}

	var diags diag.Diagnostics
	rules := p.GetRules()
	ruleValues := make([]attr.Value, len(rules))
	for i, br := range rules {
		obj, d := types.ObjectValue(riskBlockableRuleAttrTypes, map[string]attr.Value{
			"rule":    types.StringValue(br.GetRule()),
			"comment": emptyStringToNull(br.GetComment()),
			"uuid":    emptyStringToNull(br.GetUuid()),
			"name":    emptyStringToNull(br.GetName()),
		})
		diags.Append(d...)
		ruleValues[i] = obj
	}
	rulesList := types.ListNull(riskBlockableRuleObjectType)
	if len(rules) > 0 {
		var d diag.Diagnostics
		rulesList, d = types.ListValue(riskBlockableRuleObjectType, ruleValues)
		diags.Append(d...)
	}

	obj, d := types.ObjectValue(riskBlockableRulesAttrTypes, map[string]attr.Value{
		"enabled":     boolPtrToTF(p.Enabled),
		"rules":       rulesList,
		"filter_expr": emptyStringToNull(p.GetFilterExpr()),
	})
	diags.Append(d...)
	return obj, diags
}

func riskBlockableRulesObjectToProto(ctx context.Context, obj types.Object) (*apipb.BlockableRulePluginSettings, diag.Diagnostics) {
	if obj.IsNull() || obj.IsUnknown() {
		return nil, nil
	}
	var m riskBlockableRulesModel
	d := obj.As(ctx, &m, basetypes.ObjectAsOptions{})
	if d.HasError() {
		return nil, d
	}

	var rules []*apipb.BlockableRule
	if !m.Rules.IsNull() && !m.Rules.IsUnknown() {
		var rms []riskBlockableRuleModel
		d.Append(m.Rules.ElementsAs(ctx, &rms, false)...)
		if d.HasError() {
			return nil, d
		}
		rules = make([]*apipb.BlockableRule, len(rms))
		for i, rm := range rms {
			rules[i] = apipb.BlockableRule_builder{
				Rule:    rm.Rule.ValueString(),
				Comment: rm.Comment.ValueString(),
				Uuid:    rm.Uuid.ValueString(),
				Name:    rm.Name.ValueString(),
			}.Build()
		}
	}

	return apipb.BlockableRulePluginSettings_builder{
		Enabled:    tfBoolToPtr(m.Enabled),
		Rules:      rules,
		FilterExpr: m.FilterExpr.ValueString(),
	}.Build(), d
}

func riskRemotePluginsProtoToList(ctx context.Context, plugins []*apipb.RemoteRiskEnginePluginSettings) (types.List, diag.Diagnostics) {
	if len(plugins) == 0 {
		return types.ListNull(riskRemotePluginObjectType), nil
	}

	var diags diag.Diagnostics
	values := make([]attr.Value, len(plugins))
	for i, p := range plugins {
		headers := p.GetHeaders()
		var headerList types.List
		if len(headers) == 0 {
			headerList = types.ListNull(riskHttpHeaderObjectType)
		} else {
			hvalues := make([]attr.Value, len(headers))
			for j, h := range headers {
				hobj, d := types.ObjectValue(riskHttpHeaderAttrTypes, map[string]attr.Value{
					"key":   types.StringValue(h.GetKey()),
					"value": types.StringValue(h.GetValue()),
				})
				diags.Append(d...)
				hvalues[j] = hobj
			}
			var d diag.Diagnostics
			headerList, d = types.ListValue(riskHttpHeaderObjectType, hvalues)
			diags.Append(d...)
		}

		obj, d := types.ObjectValue(riskRemotePluginAttrTypes, map[string]attr.Value{
			"enabled":     boolPtrToTF(p.Enabled),
			"name":        stringPtrToTF(p.Name),
			"version":     stringPtrToTF(p.Version),
			"uuid":        stringPtrToTF(p.Uuid),
			"url":         stringPtrToTF(p.Url),
			"headers":     headerList,
			"ttl":         durationToTFString(p.GetTtl()),
			"secret":      stringPtrToTF(p.Secret),
			"filter_expr": emptyStringToNull(p.GetFilterExpr()),
		})
		diags.Append(d...)
		values[i] = obj
	}

	list, d := types.ListValue(riskRemotePluginObjectType, values)
	diags.Append(d...)
	return list, diags
}

func riskRemotePluginsListToProto(ctx context.Context, list types.List) ([]*apipb.RemoteRiskEnginePluginSettings, diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		return nil, nil
	}
	var diags diag.Diagnostics

	var ms []riskRemotePluginModel
	diags.Append(list.ElementsAs(ctx, &ms, false)...)
	if diags.HasError() {
		return nil, diags
	}

	plugins := make([]*apipb.RemoteRiskEnginePluginSettings, len(ms))
	for i, m := range ms {
		ttl, err := tfStringToDuration(m.Ttl)
		if err != nil {
			diags.AddAttributeError(path.Root("remote_plugins").AtListIndex(i).AtName("ttl"), "Invalid duration", err.Error())
			return nil, diags
		}

		var headers []*apipb.HTTPHeader
		if !m.Headers.IsNull() && !m.Headers.IsUnknown() {
			var hms []riskHttpHeaderModel
			diags.Append(m.Headers.ElementsAs(ctx, &hms, false)...)
			if diags.HasError() {
				return nil, diags
			}
			headers = make([]*apipb.HTTPHeader, len(hms))
			for j, hm := range hms {
				headers[j] = apipb.HTTPHeader_builder{
					Key:   hm.Key.ValueString(),
					Value: hm.Value.ValueString(),
				}.Build()
			}
		}

		plugins[i] = apipb.RemoteRiskEnginePluginSettings_builder{
			Enabled:    tfBoolToPtr(m.Enabled),
			Name:       tfStringToPtr(m.Name),
			Version:    tfStringToPtr(m.Version),
			Uuid:       tfStringToPtr(m.Uuid),
			Url:        tfStringToPtr(m.Url),
			Headers:    headers,
			Ttl:        ttl,
			Secret:     tfStringToPtr(m.Secret),
			FilterExpr: m.FilterExpr.ValueString(),
		}.Build()
	}

	return plugins, diags
}

// emptyStringToNull treats the protobuf "unset string" sentinel (empty string)
// as Terraform null. Used for non-presence-sensitive proto string fields that
// nonetheless should round-trip cleanly through optional schema attributes.
func emptyStringToNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}
