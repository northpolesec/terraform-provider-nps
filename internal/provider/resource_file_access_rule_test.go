// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccFileAccessRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccFileAccessRuleResourceConfig("TestRule1", "global"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_file_access_rule.test", "name", "TestRule1"),
					resource.TestCheckResourceAttr("nps_file_access_rule.test", "tag", "global"),
					resource.TestCheckResourceAttr("nps_file_access_rule.test", "rule_type", "PathsWithAllowedProcesses"),
					resource.TestCheckResourceAttr("nps_file_access_rule.test", "allow_read_access", "true"),
					resource.TestCheckResourceAttr("nps_file_access_rule.test", "block_violations", "false"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "nps_workshop_file_access_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccFileAccessRuleResourceConfig(name string, tag string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_file_access_rule" "test" {
  name              = %[1]q
  tag               = %[2]q
  rule_type         = "PathsWithAllowedProcesses"
  allow_read_access = true
  block_violations  = false

  path_prefixes = [
    "/tmp/",
  ]

  process_binary_paths = [
    "/usr/bin/test",
  ]
}
`, name, tag)
}
