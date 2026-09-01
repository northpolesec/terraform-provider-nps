// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestPackageRuleSourceAcceptedValues(t *testing.T) {
	got := packageSourceAcceptedValues()
	for _, v := range []string{"BAZEL", "PACKAGE_SOURCE_BAZEL"} {
		if slices.Contains(got, v) {
			t.Errorf("packageSourceAcceptedValues contains %q", v)
		}
	}
	for _, v := range []string{"HOMEBREW", "PACKAGE_SOURCE_HOMEBREW"} {
		if !slices.Contains(got, v) {
			t.Errorf("packageSourceAcceptedValues missing %q: %v", v, got)
		}
	}
}

func TestPackageRulePolicyAcceptedValues(t *testing.T) {
	got := packagePolicyAcceptedValues()
	if slices.Contains(got, "SEATBELT") {
		t.Errorf("packagePolicyAcceptedValues contains SEATBELT")
	}
	if !slices.Contains(got, "ALLOWLIST") {
		t.Errorf("packagePolicyAcceptedValues missing ALLOWLIST: %v", got)
	}
}

// TestPackageRuleRoundTrip checks the optional fields survive the model ->
// proto -> model round trip, and that an unset field stays null.
func TestPackageRuleRoundTrip(t *testing.T) {
	in := PackageRuleResourceModel{
		Tag:           types.StringValue("global"),
		Source:        types.StringValue("HOMEBREW"),
		Name:          types.StringValue("wget"),
		Policy:        types.StringValue("CEL"),
		RuleType:      types.StringValue("BINARY"),
		VersionRegexp: types.StringValue("^1\\."),
		VersionCEL:    types.StringValue("version_rank < 3"),
		BinaryCEL:     types.StringValue(`path.endsWith("/wget")`),
		BlockReason:   types.StringValue("MALICIOUS"),
		CELExpr:       types.StringValue("true"),
		CustomMsg:     types.StringValue("ask security"),
		CustomURL:     types.StringValue("https://example.com/help"),
	}

	var diags diag.Diagnostics
	rule := buildPackageRule(in, &diags)
	if diags.HasError() {
		t.Fatalf("buildPackageRule: %v", diags)
	}
	if rule.GetBlockReason() != apipb.Rule_BLOCK_REASON_MALICIOUS {
		t.Errorf("block_reason = %v, want BLOCK_REASON_MALICIOUS", rule.GetBlockReason())
	}

	var out PackageRuleResourceModel
	packageRuleToModel(rule, &out)

	in.Id = out.Id // Server-assigned; not part of the round trip.
	if out != in {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
	if !out.EventDetailButtonLabel.IsNull() {
		t.Errorf("unset event_detail_button_label = %v, want null", out.EventDetailButtonLabel)
	}
}

// TestPackageRuleBlockReasonSpelling checks the deprecated BLOCK_REASON_-
// prefixed spelling still builds the right proto value and, unlike a fresh
// read, is kept in state rather than rewritten to the short form.
func TestPackageRuleBlockReasonSpelling(t *testing.T) {
	var diags diag.Diagnostics
	rule := buildPackageRule(PackageRuleResourceModel{
		Policy:      types.StringValue("BLOCKLIST"),
		BlockReason: types.StringValue("BLOCK_REASON_MALICIOUS"),
	}, &diags)
	if diags.HasError() {
		t.Fatalf("buildPackageRule: %v", diags)
	}
	if rule.GetBlockReason() != apipb.Rule_BLOCK_REASON_MALICIOUS {
		t.Errorf("block_reason = %v, want BLOCK_REASON_MALICIOUS", rule.GetBlockReason())
	}

	prior := PackageRuleResourceModel{BlockReason: types.StringValue("BLOCK_REASON_MALICIOUS")}
	packageRuleToModel(rule, &prior)
	if got := prior.BlockReason.ValueString(); got != "BLOCK_REASON_MALICIOUS" {
		t.Errorf("prior spelling rewritten to %q", got)
	}

	var fresh PackageRuleResourceModel
	packageRuleToModel(rule, &fresh)
	if got := fresh.BlockReason.ValueString(); got != "MALICIOUS" {
		t.Errorf("fresh read = %q, want MALICIOUS", got)
	}
}
