// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"
)

// enumForm returns a plan modifier that suppresses spelling-only diffs on a
// prefixed proto enum attribute the configuration leaves unset: when the
// planned value and the state value normalize to the same proto name, the
// state value is kept. A configured value is never rewritten; see
// PlanModifyString. On attributes
// that also carry RequiresReplace it must be listed FIRST: modifiers chain
// in listed order, and RequiresReplace only fires when the plan value it
// receives differs from state. Semantic equality cannot do this job; the
// framework never invokes it during planning.
func enumForm(prefix string) planmodifier.String {
	return enumFormModifier{prefix: prefix}
}

type enumFormModifier struct{ prefix string }

func (m enumFormModifier) Description(context.Context) string {
	return "Treats the prefixed and bare spellings of an enum value as equal."
}

func (m enumFormModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m enumFormModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Only a value the configuration leaves unset may be rewritten. Terraform
	// rejects a plan whose value for a configured attribute differs from the
	// configuration, so swapping the state spelling in for a configured alias
	// fails the plan outright instead of suppressing a diff. A configured alias
	// converges after one apply instead: the upsert normalizes both spellings
	// to the same enum, and the read path keeps the spelling state already has.
	if !req.ConfigValue.IsNull() {
		return
	}
	if req.StateValue.IsNull() || req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if utils.NormalizeEnum(req.PlanValue.ValueString(), m.prefix) ==
		utils.NormalizeEnum(req.StateValue.ValueString(), m.prefix) {
		resp.PlanValue = req.StateValue
	}
}
