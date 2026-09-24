// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// TestFileAccessRuleTypeAcceptedValues checks the validator accepts every
// spelling of a rule type: the CamelCase form this resource documents, the bare
// proto name, and the prefixed proto name. Config generated straight from the
// API enum has to plan cleanly.
func TestFileAccessRuleTypeAcceptedValues(t *testing.T) {
	got := fileAccessRuleTypeAcceptedValues()
	for _, want := range []string{
		"PathsWithAllowedProcesses",
		"ProcessesWithDeniedPaths",
		"PATHS_WITH_ALLOWED_PROCESSES",
		"FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES",
		"FILE_ACCESS_RULE_TYPE_PROCESSES_WITH_DENIED_PATHS",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("fileAccessRuleTypeAcceptedValues missing %q: %v", want, got)
		}
	}
	if slices.Contains(got, "FILE_ACCESS_RULE_TYPE_UNSPECIFIED") {
		t.Error("fileAccessRuleTypeAcceptedValues contains UNSPECIFIED")
	}
}

func TestFileAccessRuleTypeFromString(t *testing.T) {
	for _, c := range []struct {
		in   string
		want apipb.FileAccessRuleType
		ok   bool
	}{
		{"PathsWithAllowedProcesses", apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES, true},
		{"PATHS_WITH_ALLOWED_PROCESSES", apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES, true},
		{"FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES", apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES, true},
		{"ProcessesWithDeniedPaths", apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PROCESSES_WITH_DENIED_PATHS, true},
		{"FILE_ACCESS_RULE_TYPE_UNSPECIFIED", apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_UNSPECIFIED, false},
		{"nonsense", apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_UNSPECIFIED, false},
		{"", apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_UNSPECIFIED, false},
	} {
		got, ok := fileAccessRuleTypeFromString(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("fileAccessRuleTypeFromString(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestFileAccessRuleTypeToModel checks a refresh never rewrites state over
// spelling alone, and never writes a value the schema's own validator rejects.
func TestFileAccessRuleTypeToModel(t *testing.T) {
	const proto = apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES

	for _, c := range []struct {
		name  string
		prior types.String
		rt    apipb.FileAccessRuleType
		want  types.String
	}{
		{"keeps camel case", types.StringValue("PathsWithDeniedProcesses"), proto, types.StringValue("PathsWithDeniedProcesses")},
		{"keeps bare proto spelling", types.StringValue("PATHS_WITH_DENIED_PROCESSES"), proto, types.StringValue("PATHS_WITH_DENIED_PROCESSES")},
		{"keeps prefixed proto spelling", types.StringValue("FILE_ACCESS_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES"), proto, types.StringValue("FILE_ACCESS_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES")},
		{"rewrites a real change to camel case", types.StringValue("PathsWithAllowedProcesses"), proto, types.StringValue("PathsWithDeniedProcesses")},
		{"unspecified keeps prior", types.StringValue("PathsWithAllowedProcesses"), apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_UNSPECIFIED, types.StringValue("PathsWithAllowedProcesses")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := fileAccessRuleTypeToModel(c.prior, c.rt); !got.Equal(c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestFileAccessRuleTypeFormSuppressesSpellingDiff(t *testing.T) {
	for _, c := range []struct {
		name       string
		state, pln string
		wantState  bool
	}{
		{"camel vs bare proto", "PathsWithAllowedProcesses", "PATHS_WITH_ALLOWED_PROCESSES", true},
		{"camel vs prefixed proto", "PathsWithAllowedProcesses", "FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES", true},
		{"real change is preserved", "PathsWithAllowedProcesses", "PathsWithDeniedProcesses", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp := &planmodifier.StringResponse{PlanValue: types.StringValue(c.pln)}
			fileAccessRuleTypeForm{}.PlanModifyString(context.Background(), planmodifier.StringRequest{
				StateValue: types.StringValue(c.state),
				PlanValue:  types.StringValue(c.pln),
			}, resp)

			want := c.pln
			if c.wantState {
				want = c.state
			}
			if resp.PlanValue.ValueString() != want {
				t.Errorf("got %q, want %q", resp.PlanValue.ValueString(), want)
			}
		})
	}
}

// TestBuildFileAccessRuleUnknownRuleTypeErrors checks an unresolvable rule type
// fails loudly instead of silently sending UNSPECIFIED.
func TestBuildFileAccessRuleUnknownRuleTypeErrors(t *testing.T) {
	var diags diag.Diagnostics
	rule := buildFileAccessRule(context.Background(), FileAccessRuleResourceModel{
		Tag:      types.StringValue("dev"),
		Name:     types.StringValue("secrets"),
		RuleType: types.StringValue("nonsense"),
	}, &diags)

	if rule != nil {
		t.Error("expected no rule to be built")
	}
	if !diags.HasError() {
		t.Error("expected a diagnostic for the unknown rule type")
	}
}
