// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"fmt"
	"strings"
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
				Config: testAccExampleAPIKeyResourceConfig("test-key-1", []string{"read:hosts", "write:hosts"}),
				// Use list indexing syntax (permissions.#, permissions.0, etc.) to verify
				// individual elements rather than asserting the stringified list representation.
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_apikey.test-key-1", "name", "test-key-1"),
					resource.TestCheckResourceAttr("nps_workshop_apikey.test-key-1", "permissions.#", "2"),
					resource.TestCheckResourceAttr("nps_workshop_apikey.test-key-1", "permissions.0", "read:hosts"),
					resource.TestCheckResourceAttr("nps_workshop_apikey.test-key-1", "permissions.1", "write:hosts"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccExampleAPIKeyResourceConfig(name string, permissions []string) string {
	quoted := make([]string, len(permissions))
	for i, p := range permissions {
		quoted[i] = fmt.Sprintf("%q", p)
	}
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_apikey" %[1]q {
  name = %[1]q
  permissions = [%[2]s]
}
`, name, strings.Join(quoted, ", "))
}
