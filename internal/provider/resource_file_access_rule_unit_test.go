// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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

// TestFileAccessProcessOverridesRoundTrip checks the process_overrides list
// survives the model -> proto -> model round trip, that an unset optional field
// stays absent on the wire (so the server inherits the rule's value), and that
// an unset action stays null rather than churning to UNSPECIFIED.
func TestFileAccessProcessOverridesRoundTrip(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	want := []fileAccessProcessOverrideModel{
		{
			Type:             types.StringValue("TEAM_ID"),
			Value:            types.StringValue("EQHXZ8M8AV"),
			Action:           types.StringValue("DENY"),
			EnableSilentMode: types.BoolValue(true),
			BlockMessage:     types.StringValue("nope"),
		},
		{
			// No action and no overrides at all: every optional field inherits.
			Type:  types.StringValue("SIGNING_ID"),
			Value: types.StringValue("EQHXZ8M8AV:com.google.Chrome"),
		},
	}
	list, d := types.ListValueFrom(ctx, fileAccessProcessOverrideObjectType, want)
	diags.Append(d...)
	if diags.HasError() {
		t.Fatalf("building list: %v", diags)
	}

	overrides := fileAccessProcessOverridesToProto(ctx, list, &diags)
	if diags.HasError() {
		t.Fatalf("to proto: %v", diags)
	}
	if len(overrides) != 2 {
		t.Fatalf("got %d overrides, want 2", len(overrides))
	}

	first := overrides[0]
	if first.GetType() != apipb.FileAccessProcessType_FILE_ACCESS_PROCESS_TYPE_TEAM_ID {
		t.Errorf("type: got %v", first.GetType())
	}
	if first.GetAction() != apipb.FileAccessProcessAction_FILE_ACCESS_PROCESS_ACTION_DENY {
		t.Errorf("action: got %v", first.GetAction())
	}
	if !first.HasEnableSilentMode() || !first.GetEnableSilentMode() {
		t.Error("enable_silent_mode not sent")
	}
	// The fields the config left out must be absent, not false/empty: absent is
	// what makes the server inherit the rule's own value.
	if first.HasAllowReadAccess() || first.HasEnableSilentTtyMode() || first.HasEventDetailUrl() {
		t.Error("unset optional fields were sent as present")
	}

	second := overrides[1]
	if second.GetAction() != apipb.FileAccessProcessAction_FILE_ACCESS_PROCESS_ACTION_UNSPECIFIED {
		t.Errorf("unset action: got %v, want UNSPECIFIED", second.GetAction())
	}
	if second.HasBlockMessage() {
		t.Error("unset block_message was sent as present")
	}

	got := fileAccessProcessOverridesToModel(ctx, overrides, &diags)
	if diags.HasError() {
		t.Fatalf("to model: %v", diags)
	}
	if !got.Equal(list) {
		t.Errorf("round trip mismatch:\n got %v\nwant %v", got, list)
	}
}

func TestFileAccessProcessOverridesEmptyIsNull(t *testing.T) {
	var diags diag.Diagnostics
	got := fileAccessProcessOverridesToModel(context.Background(), nil, &diags)
	if !got.IsNull() {
		t.Errorf("got %v, want a null list", got)
	}
	if fileAccessProcessOverridesToProto(context.Background(), got, &diags) != nil {
		t.Error("a null list should send no overrides")
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

// TestBuildFileAccessRuleSendsProcessOverrides checks the overrides reach the
// upsert payload, which is the whole point of exposing them.
func TestBuildFileAccessRuleSendsProcessOverrides(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	list, d := types.ListValueFrom(ctx, fileAccessProcessOverrideObjectType, []fileAccessProcessOverrideModel{{
		Type:   types.StringValue("BINARY_PATH"),
		Value:  types.StringValue("/usr/bin/curl"),
		Action: types.StringValue("AUDIT"),
	}})
	diags.Append(d...)
	if diags.HasError() {
		t.Fatalf("building list: %v", diags)
	}

	rule := buildFileAccessRule(ctx, FileAccessRuleResourceModel{
		Tag:              types.StringValue("dev"),
		Name:             types.StringValue("secrets"),
		RuleType:         types.StringValue("PathsWithAllowedProcesses"),
		ProcessOverrides: list,
	}, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	got := rule.GetProcessOverrides()
	if len(got) != 1 || got[0].GetValue() != "/usr/bin/curl" {
		t.Fatalf("process_overrides not propagated: %v", got)
	}
	if got[0].GetAction() != apipb.FileAccessProcessAction_FILE_ACCESS_PROCESS_ACTION_AUDIT {
		t.Errorf("action: got %v, want AUDIT", got[0].GetAction())
	}
}

// TestFileAccessRuleProcessOverridesRejectsEmptyList pins down the empty-vs-null
// resolution. On a plain repeated field the two mean the same thing and the
// server cannot report the difference back, so an explicitly empty list would
// refresh to null and be proposed again on every plan. Rejecting it at plan
// time leaves exactly one way to say "no overrides": omit the attribute.
func TestFileAccessRuleProcessOverridesRejectsEmptyList(t *testing.T) {
	ctx := context.Background()
	var sResp resource.SchemaResponse
	(&FileAccessRuleResource{}).Schema(ctx, resource.SchemaRequest{}, &sResp)

	attribute, ok := sResp.Schema.Attributes["process_overrides"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatal("process_overrides is not a ListNestedAttribute")
	}

	validate := func(l types.List) diag.Diagnostics {
		var diags diag.Diagnostics
		for _, v := range attribute.Validators {
			vResp := &validator.ListResponse{}
			v.ValidateList(ctx, validator.ListRequest{ConfigValue: l}, vResp)
			diags.Append(vResp.Diagnostics...)
		}
		return diags
	}

	if diags := validate(types.ListValueMust(fileAccessProcessOverrideObjectType, nil)); !diags.HasError() {
		t.Error("an empty process_overrides list should be rejected")
	}
	if diags := validate(types.ListNull(fileAccessProcessOverrideObjectType)); diags.HasError() {
		t.Errorf("an unset process_overrides should be accepted: %v", diags)
	}

	one, d := types.ListValueFrom(ctx, fileAccessProcessOverrideObjectType, []fileAccessProcessOverrideModel{{
		Type:  types.StringValue("TEAM_ID"),
		Value: types.StringValue("EQHXZ8M8AV"),
	}})
	if d.HasError() {
		t.Fatalf("building list: %v", d)
	}
	if diags := validate(one); diags.HasError() {
		t.Errorf("a single-entry process_overrides should be accepted: %v", diags)
	}
}
