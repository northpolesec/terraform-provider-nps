// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccWorkshopRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccExampleRuleResourceConfig("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", "global", "block yes"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "comment", "block yes"),
				),
			},
			{
				Config: testAccExampleRuleResourceConfig("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", "tag123", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "tag", "tag123"),
				),
			},
			{
				Config: testAccExampleRuleResourceConfig("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", "host:123", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "tag", "host:123"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccExampleRuleResourceConfig(name, identifier, ruleType, policy, tag, comment string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_rule" %[1]q {
  identifier = %[2]q
  rule_type  = %[3]q
  policy     = %[4]q
	tag        = %[5]q
	comment    = %[6]q
}
`, name, identifier, ruleType, policy, tag, comment)
}
