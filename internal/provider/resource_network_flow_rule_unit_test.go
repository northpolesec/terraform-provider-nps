// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestPortRangeHigh is the regression test for a ports.high that mapped an
// explicit 0 back to null on every read. The proto treats 0 and unset
// identically ("0 (unset) matches only low") and the wire cannot tell them
// apart, so a config with high = 0 used to diff forever.
func TestPortRangeHigh(t *testing.T) {
	nullHigh := []NetworkFlowRulePortRangeModel{{High: types.Int64Null()}}
	zeroHigh := []NetworkFlowRulePortRangeModel{{High: types.Int64Value(0)}}

	for _, c := range []struct {
		name  string
		prior []NetworkFlowRulePortRangeModel
		i     int
		high  uint32
		want  types.Int64
	}{
		{"real bound", nullHigh, 0, 8080, types.Int64Value(8080)},
		{"zero with unset prior stays null", nullHigh, 0, 0, types.Int64Null()},
		{"zero with explicit zero prior stays zero", zeroHigh, 0, 0, types.Int64Value(0)},
		{"index past prior stays null", zeroHigh, 1, 0, types.Int64Null()},
		{"no prior state stays null", nil, 0, 0, types.Int64Null()},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := portRangeHigh(c.prior, c.i, c.high); !got.Equal(c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
