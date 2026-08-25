// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/northpolesec/terraform-provider-nps/internal/utils"
)

// enumForm returns a plan modifier that suppresses spelling-only diffs on a
// prefixed proto enum attribute: when the planned value and the state value
// normalize to the same proto name, the state value is kept. On attributes
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
	if req.StateValue.IsNull() || req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if utils.NormalizeEnum(req.PlanValue.ValueString(), m.prefix) ==
		utils.NormalizeEnum(req.StateValue.ValueString(), m.prefix) {
		resp.PlanValue = req.StateValue
	}
}
