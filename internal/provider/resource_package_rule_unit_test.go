// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"slices"
	"testing"
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
