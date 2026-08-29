// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The API's scalar and repeated fields generally cannot distinguish an unset
// value from an explicitly configured empty value. When the API reports empty,
// retain an empty value only if Terraform already knew it was explicitly
// empty; otherwise use null so stale non-empty state is removed.
func normalizeAbsentOptionalString(prior types.String) types.String {
	if !prior.IsNull() && !prior.IsUnknown() && prior.ValueString() == "" {
		return prior
	}
	return types.StringNull()
}

func normalizeAbsentOptionalList(prior types.List, elementType attr.Type) types.List {
	if !prior.IsNull() && !prior.IsUnknown() && len(prior.Elements()) == 0 {
		return prior
	}
	return types.ListNull(elementType)
}

func normalizeAbsentOptionalSet(prior types.Set, elementType attr.Type) types.Set {
	if !prior.IsNull() && !prior.IsUnknown() && len(prior.Elements()) == 0 {
		return prior
	}
	return types.SetNull(elementType)
}

func normalizeAbsentOptionalSlice[T any](prior []T) []T {
	if prior != nil && len(prior) == 0 {
		return prior
	}
	return nil
}
