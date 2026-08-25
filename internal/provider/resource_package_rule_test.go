// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccPackageRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccPackageRuleResourceConfig("wget", "global"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "name", "wget"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "tag", "global"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "source", "HOMEBREW"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "policy", "ALLOWLIST"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "rule_type", "SIGNINGID"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "nps_workshop_package_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// The deprecated long spelling applies over short-form state with no diff.
			{
				Config:   testAccPackageRuleResourceConfigWithSource("wget", "global", "PACKAGE_SOURCE_HOMEBREW"),
				PlanOnly: true,
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestAccPackageRuleDeprecatedSourceSpelling covers the compatibility
// window: a config written with the long proto spelling still applies, its
// state keeps that spelling, and rewriting the config to the bare spelling
// plans as a no-op instead of a replace.
func TestAccPackageRuleDeprecatedSourceSpelling(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPackageRuleResourceConfigWithSource("jq", "global", "PACKAGE_SOURCE_HOMEBREW"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "source", "PACKAGE_SOURCE_HOMEBREW"),
				),
			},
			{
				Config:   testAccPackageRuleResourceConfigWithSource("jq", "global", "HOMEBREW"),
				PlanOnly: true,
			},
		},
	})
}

func testAccPackageRuleResourceConfig(name string, tag string) string {
	return testAccPackageRuleResourceConfigWithSource(name, tag, "HOMEBREW")
}

func testAccPackageRuleResourceConfigWithSource(name, tag, source string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_package_rule" "test" {
  name      = %[1]q
  tag       = %[2]q
  source    = %[3]q
  policy    = "ALLOWLIST"
  rule_type = "SIGNINGID"
}
`, name, tag, source)
}
