// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestBoolPtrRoundtrip(t *testing.T) {
	tr := true
	if got := boolPtrToTF(nil); !got.IsNull() {
		t.Fatalf("expected null for nil, got %v", got)
	}
	if got := boolPtrToTF(&tr); got.ValueBool() != true {
		t.Fatalf("expected true, got %v", got)
	}
	if got := tfBoolToPtr(types.BoolNull()); got != nil {
		t.Fatalf("expected nil for null bool, got %v", *got)
	}
	if got := tfBoolToPtr(types.BoolValue(true)); got == nil || *got != true {
		t.Fatalf("expected ptr to true, got %v", got)
	}
}

func TestStringPtrRoundtrip(t *testing.T) {
	s := "x"
	if got := stringPtrToTF(nil); !got.IsNull() {
		t.Fatalf("expected null for nil, got %v", got)
	}
	if got := stringPtrToTF(&s); got.ValueString() != "x" {
		t.Fatalf("expected 'x', got %v", got)
	}
	if got := tfStringToPtr(types.StringNull()); got != nil {
		t.Fatalf("expected nil for null string, got %v", *got)
	}
	if got := tfStringToPtr(types.StringValue("y")); got == nil || *got != "y" {
		t.Fatalf("expected ptr to 'y', got %v", got)
	}
}

func TestDurationConversion(t *testing.T) {
	if got := durationToTFString(nil); !got.IsNull() {
		t.Fatalf("expected null for nil duration, got %v", got)
	}
	d := durationpb.New(5 * time.Second)
	if got := durationToTFString(d); got.ValueString() != "5s" {
		t.Fatalf("expected '5s', got %v", got)
	}
	parsed, err := tfStringToDuration(types.StringValue("5s"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.AsDuration().Seconds() != 5 {
		t.Fatalf("expected 5s, got %v", parsed.AsDuration())
	}
	if got, err := tfStringToDuration(types.StringNull()); err != nil || got != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", got, err)
	}
	if _, err := tfStringToDuration(types.StringValue("not-a-duration")); err == nil {
		t.Fatal("expected error parsing invalid duration")
	}
}

func TestExportConfigProtoToModel(t *testing.T) {
	url := "gs://bucket"
	resp := apipb.GetExportConfigResponse_builder{
		AuditEventBucketUrl: &url,
	}.Build()
	got := exportConfigProtoToModel(resp)
	if got.AuditEventBucketUrl.ValueString() != "gs://bucket" {
		t.Fatalf("unexpected audit url: %v", got.AuditEventBucketUrl)
	}
	if !got.ExecutionEventBucketUrl.IsNull() {
		t.Fatalf("expected null execution url, got %v", got.ExecutionEventBucketUrl)
	}
}

func TestMPAProtoToModel(t *testing.T) {
	s := apipb.MultipartyApprovalSettings_builder{
		Enabled:           true,
		MaxDuration:       durationpb.New(24 * 3600 * 1e9),
		RequiredApprovers: 2,
		ExcludeApiKeys:    true,
	}.Build()
	got := mpaProtoToModel(s)
	if !got.Enabled.ValueBool() {
		t.Errorf("expected enabled=true")
	}
	if got.MaxDuration.ValueString() != "24h0m0s" {
		t.Errorf("expected 24h0m0s, got %q", got.MaxDuration.ValueString())
	}
	if got.RequiredApprovers.ValueInt64() != 2 {
		t.Errorf("expected 2 approvers, got %d", got.RequiredApprovers.ValueInt64())
	}
	if !got.ExcludeApiKeys.ValueBool() {
		t.Errorf("expected exclude_api_keys=true")
	}

	// nil → empty model
	empty := mpaProtoToModel(nil)
	if !empty.Enabled.IsNull() && empty.Enabled.ValueBool() {
		t.Errorf("expected null/false for nil settings")
	}
}

func TestRiskEngineRoundtrip(t *testing.T) {
	ctx := context.Background()

	en, vt := true, true
	apiKey := "vt-api-key"
	original := apipb.RiskEngineSettings_builder{
		Enabled:       &en,
		PluginTimeout: durationpb.New(5 * 1e9),
		LocalPlugins: apipb.LocalPluginSettings_builder{
			VirusTotal: apipb.VirusTotalPluginSettings_builder{
				Enabled:        &vt,
				ApiKey:         &apiKey,
				CacheTtl:       durationpb.New(30 * 60 * 1e9),
				ExcludeEngines: []string{"engine-a", "engine-b"},
				FilterExpr:     "blockable.platform == 'macos'",
			}.Build(),
		}.Build(),
		RemotePlugins: []*apipb.RemoteRiskEnginePluginSettings{
			apipb.RemoteRiskEnginePluginSettings_builder{
				Enabled: &en,
				Name:    proto.String("plugin-a"),
				Url:     proto.String("https://example.invalid/plugin"),
				Ttl:     durationpb.New(2 * 1e9),
				Headers: []*apipb.HTTPHeader{
					apipb.HTTPHeader_builder{Key: "X-Tenant", Value: "north-pole"}.Build(),
				},
			}.Build(),
		},
	}.Build()

	model, diags := riskEngineProtoToModel(ctx, original)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	round, diags := riskEngineModelToProto(ctx, &model)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if round.GetEnabled() != true {
		t.Errorf("expected enabled=true after roundtrip")
	}
	if round.GetPluginTimeout().AsDuration().Seconds() != 5 {
		t.Errorf("expected 5s plugin_timeout, got %v", round.GetPluginTimeout().AsDuration())
	}
	vtOut := round.GetLocalPlugins().GetVirusTotal()
	if vtOut == nil || vtOut.GetApiKey() != "vt-api-key" {
		t.Errorf("expected api_key=vt-api-key, got %v", vtOut)
	}
	if vtOut.GetCacheTtl().AsDuration().Minutes() != 30 {
		t.Errorf("expected 30m cache_ttl, got %v", vtOut.GetCacheTtl().AsDuration())
	}
	if got := vtOut.GetExcludeEngines(); len(got) != 2 || got[0] != "engine-a" {
		t.Errorf("unexpected engines after roundtrip: %v", got)
	}
	if vtOut.GetFilterExpr() != "blockable.platform == 'macos'" {
		t.Errorf("unexpected filter_expr after roundtrip: %q", vtOut.GetFilterExpr())
	}

	rp := round.GetRemotePlugins()
	if len(rp) != 1 {
		t.Fatalf("expected 1 remote plugin, got %d", len(rp))
	}
	if rp[0].GetName() != "plugin-a" {
		t.Errorf("expected name plugin-a, got %q", rp[0].GetName())
	}
	if len(rp[0].GetHeaders()) != 1 || rp[0].GetHeaders()[0].GetKey() != "X-Tenant" {
		t.Errorf("unexpected headers after roundtrip: %v", rp[0].GetHeaders())
	}
}

func TestAPIKeyCIDRProtoToModel(t *testing.T) {
	ctx := context.Background()

	s := apipb.APIKeyCIDRSettings_builder{
		Enabled:      true,
		AllowedCidrs: []string{"10.0.0.0/8", "192.168.1.0/24"},
	}.Build()
	got, diags := apikeyCIDRProtoToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !got.Enabled.ValueBool() {
		t.Errorf("expected enabled=true")
	}
	var cidrs []string
	got.AllowedCidrs.ElementsAs(ctx, &cidrs, false)
	if len(cidrs) != 2 || cidrs[0] != "10.0.0.0/8" {
		t.Errorf("unexpected allowed_cidrs: %v", cidrs)
	}

	// Empty allowlist maps to null, not an empty list, to avoid perpetual diffs.
	empty, _ := apikeyCIDRProtoToModel(ctx, apipb.APIKeyCIDRSettings_builder{}.Build())
	if !empty.AllowedCidrs.IsNull() {
		t.Errorf("expected null allowed_cidrs for empty settings, got %v", empty.AllowedCidrs)
	}

	// nil settings.
	nilModel, _ := apikeyCIDRProtoToModel(ctx, nil)
	if !nilModel.AllowedCidrs.IsNull() {
		t.Errorf("expected null allowed_cidrs for nil settings")
	}
}

func TestCIDRValidator(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		val     string
		wantErr bool
	}{
		{"10.0.0.0/8", false},
		{"192.168.1.0/24", false},
		{"2001:db8::/32", false},
		{"10.0.0.0", true},    // missing prefix
		{"10.0.0.0/33", true}, // invalid prefix length
		{"not-a-cidr", true},
	} {
		resp := &validator.StringResponse{}
		cidrValidator{}.ValidateString(ctx, validator.StringRequest{
			ConfigValue: types.StringValue(tc.val),
		}, resp)
		if got := resp.Diagnostics.HasError(); got != tc.wantErr {
			t.Errorf("%q: got error=%v, want error=%v", tc.val, got, tc.wantErr)
		}
	}
}

type fakeAutoUpdateClient struct {
	svcpb.WorkshopServiceClient

	settings *apipb.AutoUpdateSettings
}

func (f *fakeAutoUpdateClient) GetAutoUpdateSettings(ctx context.Context, in *apipb.GetAutoUpdateSettingsRequest, _ ...grpc.CallOption) (*apipb.GetAutoUpdateSettingsResponse, error) {
	return apipb.GetAutoUpdateSettingsResponse_builder{Settings: f.settings}.Build(), nil
}

// TestAutoUpdateReadKeepsPriorModeOnUnspecified is the regression test for a
// Read that wrote AUTO_UPDATE_MODE_UNSPECIFIED into state for a tenant with no
// stored settings. The schema's own OneOf validator rejects that value, so the
// next plan failed on state the provider itself had written.
func TestAutoUpdateReadKeepsPriorModeOnUnspecified(t *testing.T) {
	ctx := context.Background()
	prior := AutoUpdateSettingsResourceModel{
		Mode: types.StringValue("AUTO_UPDATE_MODE_ENABLED_ALL"),
	}

	read := func(settings *apipb.AutoUpdateSettings) AutoUpdateSettingsResourceModel {
		r := &AutoUpdateSettingsResource{client: &fakeAutoUpdateClient{settings: settings}}

		var sResp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sResp)
		var iResp resource.IdentitySchemaResponse
		r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)

		req := resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema}}
		if diags := req.State.Set(ctx, prior); diags.HasError() {
			t.Fatalf("failed to build state: %v", diags)
		}
		resp := &resource.ReadResponse{
			State:    tfsdk.State{Schema: sResp.Schema},
			Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
		}
		r.Read(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
		}

		var got AutoUpdateSettingsResourceModel
		if diags := resp.State.Get(ctx, &got); diags.HasError() {
			t.Fatalf("reading final state: %v", diags)
		}
		return got
	}

	got := read(apipb.AutoUpdateSettings_builder{
		Mode: apipb.AutoUpdateMode_AUTO_UPDATE_MODE_UNSPECIFIED,
	}.Build())
	if got.Mode.ValueString() != "AUTO_UPDATE_MODE_ENABLED_ALL" {
		t.Errorf("mode: got %q, want the prior value", got.Mode.ValueString())
	}

	// A concrete mode from the server still wins.
	got = read(apipb.AutoUpdateSettings_builder{
		Mode: apipb.AutoUpdateMode_AUTO_UPDATE_MODE_DISABLED,
	}.Build())
	if got.Mode.ValueString() != "AUTO_UPDATE_MODE_DISABLED" {
		t.Errorf("mode: got %q, want AUTO_UPDATE_MODE_DISABLED", got.Mode.ValueString())
	}
}

// TestAPIKeyCIDREnabledHasFalseDefault is the regression test for a bare
// Optional enabled. SetAPIKeyCIDRSettings replaces the whole message, so
// omitting the attribute really does store false and Read reports that back;
// without the default, every refresh diffed false against null forever.
func TestAPIKeyCIDREnabledHasFalseDefault(t *testing.T) {
	ctx := context.Background()
	var sResp resource.SchemaResponse
	(&APIKeyCIDRSettingsResource{}).Schema(ctx, resource.SchemaRequest{}, &sResp)

	attribute, ok := sResp.Schema.Attributes["enabled"].(schema.BoolAttribute)
	if !ok {
		t.Fatal("enabled is not a BoolAttribute")
	}
	if !attribute.Computed {
		t.Error("enabled must be Computed for its default to apply")
	}
	if attribute.Default == nil {
		t.Fatal("enabled has no default")
	}

	dResp := &defaults.BoolResponse{}
	attribute.Default.DefaultBool(ctx, defaults.BoolRequest{}, dResp)
	if dResp.PlanValue.ValueBool() {
		t.Errorf("enabled default: got %v, want false", dResp.PlanValue)
	}
}

type fakeMPAClient struct {
	svcpb.WorkshopServiceClient

	stored   *apipb.MultipartyApprovalSettings
	setCalls int
	lastSet  *apipb.SetMultipartyApprovalSettingsRequest
}

func (f *fakeMPAClient) GetMultipartyApprovalSettings(ctx context.Context, in *apipb.GetMultipartyApprovalSettingsRequest, _ ...grpc.CallOption) (*apipb.GetMultipartyApprovalSettingsResponse, error) {
	return apipb.GetMultipartyApprovalSettingsResponse_builder{Settings: f.stored}.Build(), nil
}

func (f *fakeMPAClient) SetMultipartyApprovalSettings(ctx context.Context, in *apipb.SetMultipartyApprovalSettingsRequest, _ ...grpc.CallOption) (*apipb.SetMultipartyApprovalSettingsResponse, error) {
	f.setCalls++
	f.lastSet = in
	return apipb.SetMultipartyApprovalSettingsResponse_builder{}.Build(), nil
}

// TestMPAUpdateRefreshesFromServer is the regression test for the perpetual
// diff: the attributes are Optional+Computed and the Set RPC is
// presence-sensitive, so an attribute the user leaves out of config must end up
// in state as the server's value, not the plan's null.
func TestMPAUpdateRefreshesFromServer(t *testing.T) {
	ctx := context.Background()

	fake := &fakeMPAClient{stored: apipb.MultipartyApprovalSettings_builder{
		Enabled:           true,
		RequiredApprovers: 2,
		ExcludeApiKeys:    true,
	}.Build()}
	r := &MPASettingsResource{client: fake}

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	var iResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)

	// The user configures enabled only; the other two are unset in the plan.
	plan := MPASettingsResourceModel{Enabled: types.BoolValue(true)}
	state := MPASettingsResourceModel{
		Enabled:           types.BoolValue(false),
		RequiredApprovers: types.Int64Value(2),
		ExcludeApiKeys:    types.BoolValue(true),
	}

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: sResp.Schema},
		State: tfsdk.State{Schema: sResp.Schema},
	}
	if diags := req.Plan.Set(ctx, plan); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags)
	}
	if diags := req.State.Set(ctx, state); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	resp := &resource.UpdateResponse{
		State:    tfsdk.State{Schema: sResp.Schema},
		Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
	}
	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}

	// Only the changed field is sent.
	if fake.setCalls != 1 {
		t.Fatalf("Set calls = %d, want 1", fake.setCalls)
	}
	if fake.lastSet.HasRequiredApprovers() {
		t.Error("an unconfigured required_approvers must not be sent")
	}

	var final MPASettingsResourceModel
	if diags := resp.State.Get(ctx, &final); diags.HasError() {
		t.Fatalf("reading final state: %v", diags)
	}
	if final.RequiredApprovers.ValueInt64() != 2 {
		t.Errorf("required_approvers: got %v, want the server's 2", final.RequiredApprovers)
	}
	if !final.ExcludeApiKeys.ValueBool() {
		t.Errorf("exclude_api_keys: got %v, want the server's true", final.ExcludeApiKeys)
	}
}
