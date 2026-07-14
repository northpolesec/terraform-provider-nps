// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestWebhookBasicToProtoSecretPrecedence(t *testing.T) {
	ctx := context.Background()
	nullHeaders := types.ListNull(webhookHeaderAttrTypesObject())

	// secret_wo wins when set alone.
	b, d := webhookBasicToProto(ctx, types.BoolValue(true), types.StringValue("https://x"),
		types.StringNull(), types.StringValue("wo-secret"), nullHeaders, path.Root("audit_events"))
	if d.HasError() {
		t.Fatalf("unexpected diags: %v", d)
	}
	if b.GetSecret() != "wo-secret" {
		t.Fatalf("expected wo-secret, got %q", b.GetSecret())
	}

	// regular secret used when secret_wo unset.
	b, d = webhookBasicToProto(ctx, types.BoolValue(true), types.StringValue("https://x"),
		types.StringValue("reg-secret"), types.StringNull(), nullHeaders, path.Root("audit_events"))
	if d.HasError() {
		t.Fatalf("unexpected diags: %v", d)
	}
	if b.GetSecret() != "reg-secret" {
		t.Fatalf("expected reg-secret, got %q", b.GetSecret())
	}

	// both set is an error.
	_, d = webhookBasicToProto(ctx, types.BoolValue(true), types.StringValue("https://x"),
		types.StringValue("reg"), types.StringValue("wo"), nullHeaders, path.Root("audit_events"))
	if !d.HasError() {
		t.Fatalf("expected error when both secret and secret_wo are set")
	}
}

func TestEnumsToTFPreservesPriorOnEmpty(t *testing.T) {
	ctx := context.Background()

	// Server returns nothing ("all"): preserve the user's prior representation
	// rather than flipping [] <-> null.
	priorEmpty, _ := types.ListValueFrom(ctx, types.StringType, []string{})
	got, _ := enumsToTF(ctx, []apipb.AuditEvent{}, priorEmpty)
	if got.IsNull() || len(got.Elements()) != 0 {
		t.Fatalf("expected empty (non-null) list preserved, got %v", got)
	}
	got, _ = enumsToTF(ctx, []apipb.AuditEvent{}, types.ListNull(types.StringType))
	if !got.IsNull() {
		t.Fatalf("expected null preserved, got %v", got)
	}

	// Server returns values: reflect them regardless of prior.
	got, _ = enumsToTF(ctx, []apipb.AuditEvent{apipb.AuditEvent_AUDIT_EVENT_RULE_UPSERT}, types.ListNull(types.StringType))
	if got.IsNull() || len(got.Elements()) != 1 {
		t.Fatalf("expected one element, got %v", got)
	}
}

func TestAuditEventsToProtoInvalid(t *testing.T) {
	ctx := context.Background()
	l, _ := types.ListValueFrom(ctx, types.StringType, []string{"AUDIT_EVENT_RULE_UPSERT", "NOT_A_REAL_EVENT"})
	_, d := auditEventsToProto(ctx, l, path.Root("audit_events").AtName("events"))
	if !d.HasError() {
		t.Fatalf("expected error for invalid audit event")
	}
}
