// Copyright 2024 North Pole Security, Inc.

package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccWorkshopRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			os.Setenv("NPS_ENDPOINT", "http://localhost:8080")
			os.Setenv("NPS_API_KEY", "~~UISERVER~~")
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccExampleResourceConfig("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccExampleResourceConfig(name, identifier, ruleType, policy string) string {
	return fmt.Sprintf(`
resource "nps_workshop_rule" %[1]q {
  identifier = %[2]q
  rule_type  = %[3]q
  policy     = %[4]q
}
`, name, identifier, ruleType, policy)
}
