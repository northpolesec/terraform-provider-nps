// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// TestSyncSettingsCelFallbackValidation verifies that CEL fallback expressions
// are validated before the destructive delete/update, so an invalid expression
// leaves the tag's existing settings untouched.
func TestSyncSettingsCelFallbackValidation(t *testing.T) {
	ctx := context.Background()

	for _, c := range []struct {
		name          string
		expr          string
		validateErr   error
		wantErr       bool
		wantValidated int
		wantMutated   bool
	}{
		{name: "valid", expr: "true", wantValidated: 1, wantMutated: true},
		{name: "invalid", expr: "bogus(", validateErr: errors.New("syntax error"), wantErr: true, wantValidated: 1, wantMutated: false},
		{name: "empty expr skips validation", expr: "", wantValidated: 0, wantMutated: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeWorkshopClient{validateCELErr: c.validateErr}
			r := &SyncSettingsResource{client: fake}
			data := &SyncSettingsResourceModel{
				Tag:              types.StringValue("dev"),
				TelemetryEnabled: types.BoolNull(),
				CelFallbackRule: []SyncSettingsCelFallbackRuleModel{
					{Expression: types.StringValue(c.expr)},
				},
			}

			var diags diag.Diagnostics
			ok := r.replaceTagSettings(ctx, data, types.BoolNull(), &diags)

			if diags.HasError() != c.wantErr {
				t.Errorf("HasError=%v, want %v (diags: %v)", diags.HasError(), c.wantErr, diags)
			}
			if ok == c.wantErr {
				t.Errorf("replaceTagSettings returned %v, want %v", ok, !c.wantErr)
			}
			if fake.validateCELCall != c.wantValidated {
				t.Errorf("ValidateCELRule called %d times, want %d", fake.validateCELCall, c.wantValidated)
			}
			if mutated := fake.syncDeleteCalls > 0 || fake.syncUpdateCalls > 0; mutated != c.wantMutated {
				t.Errorf("mutated=%v (delete=%d update=%d), want %v", mutated, fake.syncDeleteCalls, fake.syncUpdateCalls, c.wantMutated)
			}
		})
	}
}

// TestSyncSettingsUnsetVsEmpty verifies the central requirement: an unset
// Terraform attribute produces an absent proto field, while an attribute set
// to an empty value produces a present-but-empty proto field.
func TestSyncSettingsUnsetVsEmpty(t *testing.T) {
	ctx := context.Background()

	// allowed_path_regex explicitly empty, blocked_path_regex left unset.
	m := &SyncSettingsResourceModel{
		Tag:                        types.StringValue("dev"),
		ClientMode:                 types.StringNull(),
		AllowedPathRegex:           types.StringValue(""),
		BlockedPathRegex:           types.StringNull(),
		TelemetryFilterExpressions: types.ListNull(types.StringType),
	}

	ss, diags := syncSettingsModelToProto(ctx, m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if !ss.HasAllowedPathRegex() {
		t.Errorf("allowed_path_regex set to empty string should be present in proto")
	}
	if ss.GetAllowedPathRegex() != "" {
		t.Errorf("allowed_path_regex should be empty string, got %q", ss.GetAllowedPathRegex())
	}
	if ss.HasBlockedPathRegex() {
		t.Errorf("unset blocked_path_regex should be absent from proto")
	}
	if ss.GetClientMode() != apipb.ClientMode_UNKNOWN_CLIENT_MODE {
		t.Errorf("unset client_mode should map to UNKNOWN, got %v", ss.GetClientMode())
	}
	if ss.HasTelemetryFilterExpressions() {
		t.Errorf("unset telemetry_filter_expressions should be absent from proto")
	}
}

// TestSyncSettingsEmptyListClears verifies that an empty list (as opposed to a
// null list) is sent as a present-but-empty repeated field, which the server
// treats as an explicit clear.
func TestSyncSettingsEmptyListClears(t *testing.T) {
	ctx := context.Background()

	emptyList, d := types.ListValueFrom(ctx, types.StringType, []string{})
	if d.HasError() {
		t.Fatalf("unexpected diagnostics building empty list: %v", d)
	}

	m := &SyncSettingsResourceModel{
		Tag:                        types.StringValue("dev"),
		TelemetryFilterExpressions: emptyList,
	}

	ss, diags := syncSettingsModelToProto(ctx, m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !ss.HasTelemetryFilterExpressions() {
		t.Errorf("empty telemetry_filter_expressions list should be present in proto")
	}
	if len(ss.GetTelemetryFilterExpressions().GetValues()) != 0 {
		t.Errorf("expected empty values, got %v", ss.GetTelemetryFilterExpressions().GetValues())
	}
}

func TestSyncSettingsRoundtrip(t *testing.T) {
	ctx := context.Background()

	original := apipb.SyncSettings_builder{
		Tag:                                     "dev",
		ClientMode:                              apipb.ClientMode_MONITOR,
		EnableTransitiveRules:                   proto.Bool(true),
		AllowedPathRegex:                        proto.String(""),
		BlockedPathRegex:                        proto.String("/tmp/.*"),
		FullSyncIntervalSeconds:                 proto.Uint32(600),
		PushNotificationFullSyncIntervalSeconds: proto.Uint32(300),
		NetworkExtension: apipb.SyncSettings_NetworkExtension_builder{
			Enable: proto.Bool(true),
		}.Build(),
		TelemetryFilterExpressions: apipb.RepeatedString_builder{
			Values: []string{"has(event.Execution)"},
		}.Build(),
		CelFallbackRules: apipb.SyncSettings_CELFallbackRules_builder{
			Rules: []*apipb.SyncSettings_CELFallbackRule{
				apipb.SyncSettings_CELFallbackRule_builder{
					CelExpr:   "target.signing_id == 'foo' ? BLOCKLIST : UNSPECIFIED",
					CustomMsg: proto.String("No hypervisors!"),
				}.Build(),
			},
		}.Build(),
		OnDemandMonitorMode: apipb.OnDemandMonitorMode_builder{
			State:                  apipb.OnDemandMonitorMode_ON_DEMAND_MONITOR_MODE_STATE_ENABLED,
			MaxMinutes:             60,
			DefaultDurationMinutes: 30,
		}.Build(),
		OnDemandAdminMode: apipb.OnDemandAdminMode_builder{
			State:                  apipb.OnDemandAdminMode_ON_DEMAND_ADMIN_MODE_STATE_ENABLED,
			MaxMinutes:             120,
			DefaultDurationMinutes: 15,
			RequireJustification:   true,
		}.Build(),
		NetworkMount: apipb.SyncSettings_NetworkMount_builder{
			BlockMount:    apipb.SyncSettings_NetworkMount_BLOCK_MOUNT_ENABLED,
			BannedMessage: proto.String("blocked"),
			AllowedHosts: apipb.RepeatedString_builder{
				Values: []string{"nfs.example.com"},
			}.Build(),
		}.Build(),
		RemovableMediaPolicy: apipb.RemovableMediaPolicy_builder{
			Block: proto.Bool(true),
		}.Build(),
		EncryptedRemovableMediaPolicy: apipb.RemovableMediaPolicy_builder{
			Remount: apipb.RemountPolicy_builder{Flags: []string{"nodev", "nosuid"}}.Build(),
		}.Build(),
	}.Build()

	model, diags := syncSettingsProtoToModel(ctx, original)
	if diags.HasError() {
		t.Fatalf("proto->model diagnostics: %v", diags)
	}

	round, diags := syncSettingsModelToProto(ctx, &model)
	if diags.HasError() {
		t.Fatalf("model->proto diagnostics: %v", diags)
	}

	if round.GetTag() != "dev" {
		t.Errorf("tag mismatch: %q", round.GetTag())
	}
	if round.GetClientMode() != apipb.ClientMode_MONITOR {
		t.Errorf("client_mode mismatch: %v", round.GetClientMode())
	}
	if !round.GetEnableTransitiveRules() {
		t.Errorf("enable_transitive_rules mismatch")
	}
	if !round.HasAllowedPathRegex() || round.GetAllowedPathRegex() != "" {
		t.Errorf("allowed_path_regex empty-string roundtrip failed: present=%v value=%q",
			round.HasAllowedPathRegex(), round.GetAllowedPathRegex())
	}
	if round.GetBlockedPathRegex() != "/tmp/.*" {
		t.Errorf("blocked_path_regex mismatch: %q", round.GetBlockedPathRegex())
	}
	if round.GetFullSyncIntervalSeconds() != 600 {
		t.Errorf("full_sync_interval mismatch: %d", round.GetFullSyncIntervalSeconds())
	}
	if round.GetPushNotificationFullSyncIntervalSeconds() != 300 {
		t.Errorf("push_sync_interval mismatch: %d", round.GetPushNotificationFullSyncIntervalSeconds())
	}
	if !round.GetNetworkExtension().GetEnable() {
		t.Errorf("network_extension_enabled mismatch")
	}
	if got := round.GetTelemetryFilterExpressions().GetValues(); len(got) != 1 || got[0] != "has(event.Execution)" {
		t.Errorf("telemetry_filter_expressions mismatch: %v", got)
	}

	rules := round.GetCelFallbackRules().GetRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 cel fallback rule, got %d", len(rules))
	}
	if rules[0].GetCustomMsg() != "No hypervisors!" {
		t.Errorf("cel custom_msg mismatch: %q", rules[0].GetCustomMsg())
	}
	if rules[0].HasCustomUrl() {
		t.Errorf("cel custom_url should be absent")
	}

	odmm := round.GetOnDemandMonitorMode()
	if odmm.GetState() != apipb.OnDemandMonitorMode_ON_DEMAND_MONITOR_MODE_STATE_ENABLED {
		t.Errorf("odmm state mismatch: %v", odmm.GetState())
	}
	if odmm.GetMaxMinutes() != 60 || odmm.GetDefaultDurationMinutes() != 30 {
		t.Errorf("odmm minutes mismatch: max=%d default=%d", odmm.GetMaxMinutes(), odmm.GetDefaultDurationMinutes())
	}

	odam := round.GetOnDemandAdminMode()
	if odam.GetState() != apipb.OnDemandAdminMode_ON_DEMAND_ADMIN_MODE_STATE_ENABLED {
		t.Errorf("odam state mismatch: %v", odam.GetState())
	}
	if odam.GetMaxMinutes() != 120 || odam.GetDefaultDurationMinutes() != 15 {
		t.Errorf("odam minutes mismatch: max=%d default=%d", odam.GetMaxMinutes(), odam.GetDefaultDurationMinutes())
	}
	if !odam.GetRequireJustification() {
		t.Errorf("odam require_justification mismatch")
	}

	nm := round.GetNetworkMount()
	if nm.GetBlockMount() != apipb.SyncSettings_NetworkMount_BLOCK_MOUNT_ENABLED {
		t.Errorf("network_mount block_mount mismatch: %v", nm.GetBlockMount())
	}
	if nm.GetBannedMessage() != "blocked" {
		t.Errorf("network_mount banned_message mismatch: %q", nm.GetBannedMessage())
	}
	if got := nm.GetAllowedHosts().GetValues(); len(got) != 1 || got[0] != "nfs.example.com" {
		t.Errorf("network_mount allowed_hosts mismatch: %v", got)
	}

	if !round.GetRemovableMediaPolicy().GetBlock() {
		t.Errorf("removable_media_policy should be block")
	}
	enc := round.GetEncryptedRemovableMediaPolicy()
	if !enc.HasRemount() {
		t.Errorf("encrypted_removable_media_policy should be remount")
	}
	wantFlags := []string{"nodev", "nosuid"}
	if got := enc.GetRemount().GetFlags(); !reflect.DeepEqual(got, wantFlags) {
		t.Errorf("encrypted remount flags mismatch: got %v, want %v", got, wantFlags)
	}
}

// TestSyncSettingsRequireJustificationFalseRoundtrip ensures an explicit
// require_justification = false survives proto->model->proto rather than
// drifting to null (which would cause a perpetual diff after refresh).
func TestSyncSettingsRequireJustificationFalseRoundtrip(t *testing.T) {
	ctx := context.Background()

	original := apipb.SyncSettings_builder{
		Tag: "dev",
		OnDemandAdminMode: apipb.OnDemandAdminMode_builder{
			State:                apipb.OnDemandAdminMode_ON_DEMAND_ADMIN_MODE_STATE_ENABLED,
			RequireJustification: false,
		}.Build(),
	}.Build()

	model, diags := syncSettingsProtoToModel(ctx, original)
	if diags.HasError() {
		t.Fatalf("proto->model diagnostics: %v", diags)
	}
	if model.OnDemandAdminMode == nil {
		t.Fatalf("expected on_demand_admin_mode block")
	}
	if got := model.OnDemandAdminMode.RequireJustification; got.IsNull() || got.ValueBool() {
		t.Errorf("require_justification should round-trip to explicit false, got %v", got)
	}

	round, diags := syncSettingsModelToProto(ctx, &model)
	if diags.HasError() {
		t.Fatalf("model->proto diagnostics: %v", diags)
	}
	if round.GetOnDemandAdminMode().GetRequireJustification() {
		t.Errorf("require_justification should remain false after roundtrip")
	}
}

// TestSyncSettingsClientModeUnknownIsNull ensures an UNKNOWN client mode from
// the server maps to a null Terraform value (no spurious diff).
func TestSyncSettingsClientModeUnknownIsNull(t *testing.T) {
	ctx := context.Background()
	ss := apipb.SyncSettings_builder{Tag: "dev"}.Build()
	model, diags := syncSettingsProtoToModel(ctx, ss)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !model.ClientMode.IsNull() {
		t.Errorf("expected null client_mode, got %v", model.ClientMode)
	}
	if !model.AllowedPathRegex.IsNull() {
		t.Errorf("expected null allowed_path_regex, got %v", model.AllowedPathRegex)
	}
	if !model.TelemetryFilterExpressions.IsNull() {
		t.Errorf("expected null telemetry_filter_expressions, got %v", model.TelemetryFilterExpressions)
	}
	if model.OnDemandMonitorMode != nil {
		t.Errorf("expected nil on_demand_monitor_mode block")
	}
	if model.OnDemandAdminMode != nil {
		t.Errorf("expected nil on_demand_admin_mode block")
	}
}

// TestSyncSettingsPreviouslyDroppedFieldsRoundtrip is the regression test for
// the fields the model did not carry. This resource does a delete-then-update
// on every apply, so an unmodelled field was not merely unmanaged: it was
// destroyed the first time Terraform touched the tag.
func TestSyncSettingsPreviouslyDroppedFieldsRoundtrip(t *testing.T) {
	ctx := context.Background()

	original := apipb.SyncSettings_builder{
		Tag:                       "dev",
		BatchSize:                 proto.Uint32(250),
		EnableAllEventUpload:      proto.Bool(true),
		AutoBundleInventory:       proto.Bool(false),
		StorePlatformBinaryEvents: proto.Bool(true),
		NetworkExtension: apipb.SyncSettings_NetworkExtension_builder{
			Enable:            proto.Bool(true),
			FlowDefaultAction: apipb.NetworkFlowDefaultAction_NETWORK_FLOW_DEFAULT_ACTION_DENY.Enum(),
		}.Build(),
		CelFallbackRules: apipb.SyncSettings_CELFallbackRules_builder{
			Rules: []*apipb.SyncSettings_CELFallbackRule{
				apipb.SyncSettings_CELFallbackRule_builder{
					CelExpr:                "true",
					EventDetailButtonLabel: proto.String("Ask IT"),
				}.Build(),
			},
		}.Build(),
		ProcessOverrides: apipb.SyncSettings_ProcessOverrides_builder{
			Overrides: []*apipb.FileAccessRule_ProcessOverride{
				apipb.FileAccessRule_ProcessOverride_builder{
					Type:   apipb.FileAccessProcessType_FILE_ACCESS_PROCESS_TYPE_TEAM_ID,
					Value:  "EQHXZ8M8AV",
					Action: apipb.FileAccessProcessAction_FILE_ACCESS_PROCESS_ACTION_DENY,
				}.Build(),
			},
		}.Build(),
	}.Build()

	model, diags := syncSettingsProtoToModel(ctx, original)
	if diags.HasError() {
		t.Fatalf("proto -> model: %v", diags)
	}

	round, diags := syncSettingsModelToProto(ctx, &model)
	if diags.HasError() {
		t.Fatalf("model -> proto: %v", diags)
	}

	if round.GetBatchSize() != 250 {
		t.Errorf("batch_size: got %d, want 250", round.GetBatchSize())
	}
	if !round.GetEnableAllEventUpload() {
		t.Error("enable_all_event_upload erased")
	}
	if !round.HasAutoBundleInventory() || round.GetAutoBundleInventory() {
		t.Error("an explicit auto_bundle_inventory = false did not survive")
	}
	if !round.GetStorePlatformBinaryEvents() {
		t.Error("store_platform_binary_events erased")
	}

	ne := round.GetNetworkExtension()
	if ne == nil || !ne.GetEnable() {
		t.Fatalf("network extension erased: %v", ne)
	}
	if ne.GetFlowDefaultAction() != apipb.NetworkFlowDefaultAction_NETWORK_FLOW_DEFAULT_ACTION_DENY {
		t.Errorf("flow_default_action: got %v, want DENY", ne.GetFlowDefaultAction())
	}

	rules := round.GetCelFallbackRules().GetRules()
	if len(rules) != 1 || rules[0].GetEventDetailButtonLabel() != "Ask IT" {
		t.Errorf("cel fallback event_detail_button_label erased: %v", rules)
	}

	overrides := round.GetProcessOverrides().GetOverrides()
	if len(overrides) != 1 || overrides[0].GetValue() != "EQHXZ8M8AV" {
		t.Fatalf("process_overrides erased: %v", overrides)
	}
	if overrides[0].GetAction() != apipb.FileAccessProcessAction_FILE_ACCESS_PROCESS_ACTION_DENY {
		t.Errorf("override action: got %v, want DENY", overrides[0].GetAction())
	}
}

// TestSyncSettingsProcessOverridesUnsetVsEmpty checks the presence distinction
// the proto documents: absent means "inherit from a lower-precedence tag",
// while an empty list means "managed, explicitly no overrides".
func TestSyncSettingsProcessOverridesUnsetVsEmpty(t *testing.T) {
	ctx := context.Background()

	unset, diags := syncSettingsProtoToModel(ctx, apipb.SyncSettings_builder{Tag: "dev"}.Build())
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !unset.ProcessOverrides.IsNull() {
		t.Errorf("absent process_overrides should be null, got %v", unset.ProcessOverrides)
	}
	if round, _ := syncSettingsModelToProto(ctx, &unset); round.HasProcessOverrides() {
		t.Error("a null process_overrides must send no message")
	}

	empty, diags := syncSettingsProtoToModel(ctx, apipb.SyncSettings_builder{
		Tag:              "dev",
		ProcessOverrides: apipb.SyncSettings_ProcessOverrides_builder{}.Build(),
	}.Build())
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if empty.ProcessOverrides.IsNull() || len(empty.ProcessOverrides.Elements()) != 0 {
		t.Errorf("an empty process_overrides should be an empty list, got %v", empty.ProcessOverrides)
	}
	round, diags := syncSettingsModelToProto(ctx, &empty)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !round.HasProcessOverrides() || len(round.GetProcessOverrides().GetOverrides()) != 0 {
		t.Error("an empty process_overrides must send an empty message")
	}
}

// TestSyncSettingsOnDemandUnspecifiedStateIsNull checks a server-reported
// UNSPECIFIED state is not written into state. The schema's own OneOf validator
// rejects it, so writing it made the next plan fail on state the provider wrote.
func TestSyncSettingsOnDemandUnspecifiedStateIsNull(t *testing.T) {
	ctx := context.Background()

	model, diags := syncSettingsProtoToModel(ctx, apipb.SyncSettings_builder{
		Tag:                 "dev",
		OnDemandMonitorMode: apipb.OnDemandMonitorMode_builder{MaxMinutes: 60}.Build(),
		OnDemandAdminMode:   apipb.OnDemandAdminMode_builder{MaxMinutes: 30}.Build(),
	}.Build())
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.OnDemandMonitorMode == nil || !model.OnDemandMonitorMode.State.IsNull() {
		t.Errorf("monitor mode state: got %v, want null", model.OnDemandMonitorMode)
	}
	if model.OnDemandAdminMode == nil || !model.OnDemandAdminMode.State.IsNull() {
		t.Errorf("admin mode state: got %v, want null", model.OnDemandAdminMode)
	}
}

// TestSyncSettingsCelFallbackButtonLabelLength pins the label to the max_len
// the API enforces, so an over-long value fails the plan rather than the apply.
func TestSyncSettingsCelFallbackButtonLabelLength(t *testing.T) {
	ctx := context.Background()
	var sResp resource.SchemaResponse
	(&SyncSettingsResource{}).Schema(ctx, resource.SchemaRequest{}, &sResp)

	block, ok := sResp.Schema.Blocks["cel_fallback_rule"].(schema.ListNestedBlock)
	if !ok {
		t.Fatal("cel_fallback_rule is not a ListNestedBlock")
	}
	attribute, ok := block.NestedObject.Attributes["event_detail_button_label"].(schema.StringAttribute)
	if !ok {
		t.Fatal("event_detail_button_label is not a StringAttribute")
	}

	validate := func(s string) diag.Diagnostics {
		var diags diag.Diagnostics
		for _, v := range attribute.Validators {
			vResp := &validator.StringResponse{}
			v.ValidateString(ctx, validator.StringRequest{ConfigValue: types.StringValue(s)}, vResp)
			diags.Append(vResp.Diagnostics...)
		}
		return diags
	}

	if diags := validate(strings.Repeat("a", celFallbackButtonLabelMaxLen)); diags.HasError() {
		t.Errorf("a %d-character label should be accepted: %v", celFallbackButtonLabelMaxLen, diags)
	}
	if diags := validate(strings.Repeat("a", celFallbackButtonLabelMaxLen+1)); !diags.HasError() {
		t.Errorf("a %d-character label should be rejected", celFallbackButtonLabelMaxLen+1)
	}
}

// TestSyncSettingsProcessOverridesRejectsDuplicates checks a duplicate
// (type, value) pair fails at plan time. The server requires the pair to be
// unique and this resource deletes the tag's settings before writing the new
// ones, so a server-side rejection would leave the tag with nothing.
func TestSyncSettingsProcessOverridesRejectsDuplicates(t *testing.T) {
	ctx := context.Background()
	r := &SyncSettingsResource{}

	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)

	validate := func(overrides []fileAccessProcessOverrideModel) diag.Diagnostics {
		list, d := types.ListValueFrom(ctx, fileAccessProcessOverrideObjectType, overrides)
		if d.HasError() {
			t.Fatalf("building list: %v", d)
		}
		// tfsdk.Config has no Set, so round-trip the model through a State to
		// get the raw value the validators read.
		st := tfsdk.State{Schema: sResp.Schema}
		if diags := st.Set(ctx, SyncSettingsResourceModel{
			Tag:                        types.StringValue("dev"),
			ProcessOverrides:           list,
			TelemetryFilterExpressions: types.ListNull(types.StringType),
		}); diags.HasError() {
			t.Fatalf("building config: %v", diags)
		}
		cfg := tfsdk.Config{Schema: sResp.Schema, Raw: st.Raw}

		var all diag.Diagnostics
		for _, cv := range r.ConfigValidators(ctx) {
			vResp := &resource.ValidateConfigResponse{}
			cv.ValidateResource(ctx, resource.ValidateConfigRequest{Config: cfg}, vResp)
			all.Append(vResp.Diagnostics...)
		}
		return all
	}

	entry := func(typ, value, action string) fileAccessProcessOverrideModel {
		return fileAccessProcessOverrideModel{
			Type:   types.StringValue(typ),
			Value:  types.StringValue(value),
			Action: types.StringValue(action),
		}
	}

	if diags := validate([]fileAccessProcessOverrideModel{
		entry("TEAM_ID", "EQHXZ8M8AV", "DENY"),
		entry("SIGNING_ID", "EQHXZ8M8AV", "ALLOW"),
	}); diags.HasError() {
		t.Errorf("distinct matchers should be accepted: %v", diags)
	}

	if diags := validate([]fileAccessProcessOverrideModel{
		entry("TEAM_ID", "EQHXZ8M8AV", "DENY"),
		entry("TEAM_ID", "EQHXZ8M8AV", "ALLOW"),
	}); !diags.HasError() {
		t.Error("a duplicate (type, value) should be rejected")
	}

	// The two accepted spellings of a matcher type are the same matcher.
	if diags := validate([]fileAccessProcessOverrideModel{
		entry("TEAM_ID", "EQHXZ8M8AV", "DENY"),
		entry("FILE_ACCESS_PROCESS_TYPE_TEAM_ID", "EQHXZ8M8AV", "ALLOW"),
	}); !diags.HasError() {
		t.Error("a duplicate spelled with the prefixed alias should be rejected")
	}
}
