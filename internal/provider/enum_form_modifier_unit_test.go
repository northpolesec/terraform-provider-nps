// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestEnumFormModifier guards the compatibility window for prefixed enum
// spellings: a config rewrite between the long and short spelling of the
// same value must not plan as a change (on source, a change means a
// destroy/recreate via RequiresReplace).
func TestEnumFormModifier(t *testing.T) {
	tests := []struct {
		name  string
		state types.String
		plan  types.String
		want  types.String
	}{
		{"short plan over long state keeps state", types.StringValue("PACKAGE_SOURCE_HOMEBREW"), types.StringValue("HOMEBREW"), types.StringValue("PACKAGE_SOURCE_HOMEBREW")},
		{"long plan over short state keeps state", types.StringValue("HOMEBREW"), types.StringValue("PACKAGE_SOURCE_HOMEBREW"), types.StringValue("HOMEBREW")},
		{"real change passes through", types.StringValue("PACKAGE_SOURCE_HOMEBREW"), types.StringValue("NPM"), types.StringValue("NPM")},
		{"create leaves null state untouched", types.StringNull(), types.StringValue("HOMEBREW"), types.StringValue("HOMEBREW")},
		{"destroy leaves null plan untouched", types.StringValue("HOMEBREW"), types.StringNull(), types.StringNull()},
		{"unknown plan untouched", types.StringValue("HOMEBREW"), types.StringUnknown(), types.StringUnknown()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := planmodifier.StringRequest{StateValue: tt.state, PlanValue: tt.plan}
			resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}
			enumForm("PACKAGE_SOURCE_").PlanModifyString(context.Background(), req, resp)
			if !resp.PlanValue.Equal(tt.want) {
				t.Errorf("PlanValue = %v, want %v", resp.PlanValue, tt.want)
			}
		})
	}
}

// TestEnumFormLeavesConfiguredValueAlone is the regression test for a modifier
// that rewrote a configured alias to the state spelling. Terraform rejects a
// plan whose value for a configured attribute differs from the configuration,
// so that produced "Provider produced invalid plan" rather than suppressing a
// diff.
func TestEnumFormLeavesConfiguredValueAlone(t *testing.T) {
	const prefix = "OS_TYPE_"

	for _, c := range []struct {
		name        string
		config      types.String
		state, plan string
		want        string
	}{
		{
			name:   "configured alias is preserved",
			config: types.StringValue("OS_TYPE_MACOS"),
			state:  "MACOS", plan: "OS_TYPE_MACOS", want: "OS_TYPE_MACOS",
		},
		{
			name:   "configured value equal to state is untouched",
			config: types.StringValue("MACOS"),
			state:  "MACOS", plan: "MACOS", want: "MACOS",
		},
		{
			name:   "unconfigured value still takes the state spelling",
			config: types.StringNull(),
			state:  "OS_TYPE_MACOS", plan: "MACOS", want: "OS_TYPE_MACOS",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp := &planmodifier.StringResponse{PlanValue: types.StringValue(c.plan)}
			enumForm(prefix).PlanModifyString(context.Background(), planmodifier.StringRequest{
				ConfigValue: c.config,
				StateValue:  types.StringValue(c.state),
				PlanValue:   types.StringValue(c.plan),
			}, resp)
			if resp.PlanValue.ValueString() != c.want {
				t.Errorf("got %q, want %q", resp.PlanValue.ValueString(), c.want)
			}
		})
	}
}
