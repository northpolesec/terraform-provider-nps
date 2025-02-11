// Copyright 2025 North Pole Security, Inc.

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccWorkshopAPIKey(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccExampleAPIKeyResourceConfig("test-key-1", "superadmin"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_apikey.test-key-1", "name", "test-key-1"),
					resource.TestCheckResourceAttr("nps_workshop_apikey.test-key-1", "role", "superadmin"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccExampleAPIKeyResourceConfig(name, role string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
	insecure = true
}

resource "nps_workshop_apikey" %[1]q {
  name = %[1]q
  role = %[2]q
}
`, name, role)
}
