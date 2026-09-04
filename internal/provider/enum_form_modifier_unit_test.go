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
