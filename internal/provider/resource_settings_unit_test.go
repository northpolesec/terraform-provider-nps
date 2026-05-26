// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/durationpb"

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
				Name:    strPtr("plugin-a"),
				Url:     strPtr("https://example.invalid/plugin"),
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

func strPtr(s string) *string { return &s }
