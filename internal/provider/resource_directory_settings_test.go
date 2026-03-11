// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccWorkshopDirectorySettings_local(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with LOCAL type
			{
				Config: testAccDirectorySettingsConfig_local(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_type", "DIRECTORY_TYPE_LOCAL"),
				),
			},
			// ImportState testing
			{
				ResourceName:                         "nps_workshop_directory_settings.test",
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "directory_type",
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccWorkshopDirectorySettings_dsync(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with DSYNC type and group filter (tags must exist)
			{
				Config: testAccDirectorySettingsConfig_dsyncWithGroups(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_type", "DIRECTORY_TYPE_DSYNC"),
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_sync_group_filter.#", "2"),
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_sync_group_filter.0.id", "group-1"),
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_sync_group_filter.0.tags.#", "1"),
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_sync_group_filter.0.tags.0", "ds-test-tag-1"),
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_sync_group_filter.1.id", "group-2"),
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_sync_group_filter.1.tags.#", "1"),
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_sync_group_filter.1.tags.0", "ds-test-tag-2"),
				),
			},
			// Update to LOCAL (removes group filter)
			{
				Config: testAccDirectorySettingsConfig_local(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_type", "DIRECTORY_TYPE_LOCAL"),
				),
			},
			// Update back to DSYNC with group filter
			{
				Config: testAccDirectorySettingsConfig_dsyncWithGroups(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_type", "DIRECTORY_TYPE_DSYNC"),
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_sync_group_filter.#", "2"),
				),
			},
			// ImportState testing
			{
				ResourceName:                         "nps_workshop_directory_settings.test",
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "directory_type",
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccWorkshopDirectorySettings_dsyncNoFilter(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with DSYNC type but no group filter
			{
				Config: testAccDirectorySettingsConfig_dsyncNoFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_directory_settings.test", "directory_type", "DIRECTORY_TYPE_DSYNC"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccDirectorySettingsConfig_local() string {
	return `
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_directory_settings" "test" {
  directory_type = "DIRECTORY_TYPE_LOCAL"
}
`
}

func testAccDirectorySettingsConfig_dsyncWithGroups() string {
	return `
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_tag" "ds-test-tag-1" {
  name = "ds-test-tag-1"
}

resource "nps_workshop_tag" "ds-test-tag-2" {
  name = "ds-test-tag-2"
}

resource "nps_workshop_directory_settings" "test" {
  directory_type = "DIRECTORY_TYPE_DSYNC"

  directory_sync_group_filter {
    id   = "group-1"
    tags = [nps_workshop_tag.ds-test-tag-1.name]
  }

  directory_sync_group_filter {
    id   = "group-2"
    tags = [nps_workshop_tag.ds-test-tag-2.name]
  }
}
`
}

func testAccDirectorySettingsConfig_dsyncNoFilter() string {
	return `
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_directory_settings" "test" {
  directory_type = "DIRECTORY_TYPE_DSYNC"
}
`
}
