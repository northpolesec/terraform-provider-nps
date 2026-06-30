// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccNetworkFlowRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccNetworkFlowRuleResourceConfig("TestRule1", "global"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "name", "TestRule1"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "tag", "global"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "action", "NETWORK_FLOW_RULE_ACTION_DENY"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "direction", "NETWORK_FLOW_DIRECTION_OUTGOING"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "ports.0.low", "443"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "ports.0.high", "443"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "nps_workshop_network_flow_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccNetworkFlowRuleResourceConfig(name string, tag string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_network_flow_rule" "test" {
  name      = %[1]q
  tag       = %[2]q
  action    = "NETWORK_FLOW_RULE_ACTION_DENY"
  direction = "NETWORK_FLOW_DIRECTION_OUTGOING"

  process_signing_ids = [
    "EQHXZ8M8AV:com.google.Chrome",
  ]

  remote_domains = [
    "example.com",
  ]

  ports {
    low  = 443
    high = 443
  }

  protocols = [6]
}
`, name, tag)
}
