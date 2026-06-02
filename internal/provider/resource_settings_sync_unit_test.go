// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

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
}
