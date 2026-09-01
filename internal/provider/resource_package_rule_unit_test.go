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

// TestPackageRuleToModelClearsAbsentFields checks a refresh reflects the
// server: an optional field the server no longer reports is cleared from
// state, so clearing it outside Terraform shows as drift instead of being
// masked by the prior value.
func TestPackageRuleToModelClearsAbsentFields(t *testing.T) {
	// Fully populated prior state, as written by an earlier apply.
	data := PackageRuleResourceModel{
		Tag:                    types.StringValue("global"),
		Source:                 types.StringValue("HOMEBREW"),
		Name:                   types.StringValue("wget"),
		Policy:                 types.StringValue("CEL"),
		RuleType:               types.StringValue("BINARY"),
		MinDate:                types.StringValue("2025-01-01T00:00:00Z"),
		MaxDate:                types.StringValue("2025-12-31T00:00:00Z"),
		VersionRegexp:          types.StringValue("^1\\."),
		VersionCEL:             types.StringValue("version_rank < 3"),
		BinaryCEL:              types.StringValue(`path.endsWith("/wget")`),
		BlockReason:            types.StringValue("MALICIOUS"),
		CELExpr:                types.StringValue("true"),
		CustomMsg:              types.StringValue("ask security"),
		CustomURL:              types.StringValue("https://example.com/help"),
		EventDetailButtonLabel: types.StringValue("Request access"),
	}

	// The server reports only the required fields: every optional one was
	// cleared out of band.
	packageRuleToModel(apipb.PackageRule_builder{
		RuleId:   1,
		Tag:      "global",
		Source:   apipb.PackageSource_PACKAGE_SOURCE_HOMEBREW,
		Name:     "wget",
		Policy:   apipb.Policy_ALLOWLIST,
		RuleType: apipb.RuleType_BINARY,
	}.Build(), &data)

	for _, f := range []struct {
		name string
		got  types.String
	}{
		{"min_date", data.MinDate},
		{"max_date", data.MaxDate},
		{"version_regexp", data.VersionRegexp},
		{"version_cel", data.VersionCEL},
		{"binary_cel", data.BinaryCEL},
		{"block_reason", data.BlockReason},
		{"cel_expr", data.CELExpr},
		{"custom_msg", data.CustomMsg},
		{"custom_url", data.CustomURL},
		{"event_detail_button_label", data.EventDetailButtonLabel},
	} {
		if !f.got.IsNull() {
			t.Errorf("%s = %q, want null", f.name, f.got.ValueString())
		}
	}
	// The required fields still track the server.
	if data.Policy.ValueString() != "ALLOWLIST" {
		t.Errorf("policy = %q, want ALLOWLIST", data.Policy.ValueString())
	}
}
