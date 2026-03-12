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
				Config: testAccExampleRuleResourceConfigGlobal("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", "block yes"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "comment", "block yes"),
				),
			},
			{
				Config: testAccRuleResourceConfigWithTag("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", "rule-test-tag", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "tag", "rule-test-tag"),
				),
			},
			{
				Config: testAccExampleRuleResourceConfigGlobal("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "tag", "global"),
				),
			},
			// ImportState testing
			{
				ResourceName:            "nps_workshop_rule.yes",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccExampleRuleResourceConfigGlobal(name, identifier, ruleType, policy, comment string) string {
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
	block_reason = %[7]q
}
`, name, identifier, ruleType, policy, "global", comment, "BLOCK_REASON_POLICY")
}

func testAccRuleResourceConfigWithTag(name, identifier, ruleType, policy, tag, comment string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_tag" %[5]q {
  name = %[5]q
}

resource "nps_workshop_rule" %[1]q {
  identifier = %[2]q
  rule_type  = %[3]q
  policy     = %[4]q
  tag        = nps_workshop_tag.%[5]s.name
  comment    = %[6]q
  block_reason = %[7]q
}
`, name, identifier, ruleType, policy, tag, comment, "BLOCK_REASON_POLICY")
}
