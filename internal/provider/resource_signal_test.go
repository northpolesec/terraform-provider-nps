// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSignal(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccSignalResourceConfig("CRED-001", "global", "SEVERITY_HIGH", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_signal.test", "name", "CRED-001"),
					resource.TestCheckResourceAttr("nps_workshop_signal.test", "tag", "global"),
					resource.TestCheckResourceAttr("nps_workshop_signal.test", "severity", "SEVERITY_HIGH"),
					resource.TestCheckResourceAttr("nps_workshop_signal.test", "disabled", "false"),
				),
			},
			// In-place (non-key) update: name and tag are unchanged, so the upsert
			// supersedes the existing signal without a replace.
			{
				Config: testAccSignalResourceConfig("CRED-001", "global", "SEVERITY_CRITICAL", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_signal.test", "severity", "SEVERITY_CRITICAL"),
					resource.TestCheckResourceAttr("nps_workshop_signal.test", "disabled", "true"),
				),
			},
			// Key-changing update: name is RequiresReplace, so changing it forces
			// the signal to be replaced (destroy + create) rather than updated in
			// place.
			{
				Config: testAccSignalResourceConfig("CRED-002", "global", "SEVERITY_CRITICAL", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_signal.test", "name", "CRED-002"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "nps_workshop_signal.test",
				ImportState:       true,
				ImportStateId:     "global/CRED-002",
				ImportStateVerify: true,
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccSignalResourceConfig(name, tag, severity string, disabled bool) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_signal" "test" {
  name        = %[1]q
  tag         = %[2]q
  description = "Access to the Chrome cookie store"
  severity    = %[3]q
  expression  = "event.file.path.endsWith('/Cookies')"
  disabled    = %[4]t
}
`, name, tag, severity, disabled)
}
