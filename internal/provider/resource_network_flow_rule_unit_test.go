// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
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

// TestDNSResponse covers the server storing NXDOMAIN for a denying DNS rule
// that leaves dns_response unset: that must read back as null, not diff
// forever, while an explicit NXDOMAIN must stay NXDOMAIN.
func TestDNSResponse(t *testing.T) {
	const (
		unset    = apipb.NetworkFlowRuleDNSResponse_NETWORK_FLOW_RULE_DNS_RESPONSE_UNSPECIFIED
		nxdomain = apipb.NetworkFlowRuleDNSResponse_NETWORK_FLOW_RULE_DNS_RESPONSE_NXDOMAIN
		nodata   = apipb.NetworkFlowRuleDNSResponse_NETWORK_FLOW_RULE_DNS_RESPONSE_NODATA
	)
	for _, c := range []struct {
		name  string
		prior types.String
		r     apipb.NetworkFlowRuleDNSResponse
		want  types.String
	}{
		{"unspecified is null", types.StringValue("NODATA"), unset, types.StringNull()},
		{"stored NXDOMAIN with unset prior stays null", types.StringNull(), nxdomain, types.StringNull()},
		{"explicit NXDOMAIN stays NXDOMAIN", types.StringValue("NXDOMAIN"), nxdomain, types.StringValue("NXDOMAIN")},
		{"NODATA with unset prior is NODATA", types.StringNull(), nodata, types.StringValue("NODATA")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := dnsResponse(c.prior, c.r); !got.Equal(c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
