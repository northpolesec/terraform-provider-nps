// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestRuleReadFilter(t *testing.T) {
	tests := []struct {
		name     string
		data     RuleResourceModel
		expected string
	}{
		{
			name: "import: only ID is set",
			data: RuleResourceModel{
				Id: types.StringValue("rule-123"),
			},
			expected: `rule_id = "rule-123"`,
		},
		{
			name: "normal read: all fields set",
			data: RuleResourceModel{
				Id:         types.StringValue("rule-123"),
				Identifier: types.StringValue("platform:com.apple.yes"),
				RuleType:   types.StringValue("SIGNINGID"),
				Tag:        types.StringValue("global"),
			},
			expected: `rule_id = "rule-123" OR (identifier = "platform:com.apple.yes" AND rule_type = "SIGNINGID" AND tag = "global")`,
		},
		{
			name: "rule_type is null",
			data: RuleResourceModel{
				Id:         types.StringValue("rule-123"),
				Identifier: types.StringValue("platform:com.apple.yes"),
				RuleType:   types.StringNull(),
				Tag:        types.StringValue("global"),
			},
			expected: `rule_id = "rule-123"`,
		},
		{
			name: "rule_type is unknown",
			data: RuleResourceModel{
				Id:         types.StringValue("rule-123"),
				Identifier: types.StringValue("platform:com.apple.yes"),
				RuleType:   types.StringUnknown(),
				Tag:        types.StringValue("global"),
			},
			expected: `rule_id = "rule-123"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleReadFilter(tt.data)
			if got != tt.expected {
				t.Errorf("ruleReadFilter() = %q, want %q", got, tt.expected)
			}
		})
	}
}
