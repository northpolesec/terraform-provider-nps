// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"testing"

	frameworkresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestConfiguredDeletePackageExecutionRules(t *testing.T) {
	tests := []struct {
		name  string
		value types.Bool
		want  bool
	}{
		{name: "null defaults false", value: types.BoolNull(), want: false},
		{name: "unknown defaults false", value: types.BoolUnknown(), want: false},
		{name: "explicit false", value: types.BoolValue(false), want: false},
		{name: "explicit true", value: types.BoolValue(true), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configuredDeletePackageExecutionRules(tt.value); got != tt.want {
				t.Fatalf("configuredDeletePackageExecutionRules() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPackageRuleConfigureReceivesDeletePolicy(t *testing.T) {
	fake := &fakeWorkshopClient{}
	r := &PackageRuleResource{}
	var resp frameworkresource.ConfigureResponse

	r.Configure(context.Background(), frameworkresource.ConfigureRequest{
		ProviderData: &NPSProviderResourceData{
			Client:                      fake,
			DeletePackageExecutionRules: true,
		},
	}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected configure diagnostics: %v", resp.Diagnostics)
	}
	if r.client != fake {
		t.Fatal("package rule resource did not receive the configured client")
	}
	if !r.deleteExecutionRules {
		t.Fatal("package rule resource did not receive delete_package_execution_rules=true")
	}
}

func TestPackageRuleDeleteRequestUsesProviderSetting(t *testing.T) {
	for _, deleteChildren := range []bool{false, true} {
		req := packageRuleDeleteRequest(42, deleteChildren)
		if got := req.GetRuleId(); got != 42 {
			t.Fatalf("rule ID = %d, want 42", got)
		}
		if got := req.GetDeleteExecutionRules(); got != deleteChildren {
			t.Fatalf("DeleteExecutionRules = %v, want %v", got, deleteChildren)
		}
	}
}

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
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "source", "PACKAGE_SOURCE_HOMEBREW"),
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
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccPackageRuleResourceConfig(name string, tag string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_package_rule" "test" {
  name      = %[1]q
  tag       = %[2]q
  source    = "PACKAGE_SOURCE_HOMEBREW"
  policy    = "ALLOWLIST"
  rule_type = "SIGNINGID"
}
`, name, tag)
}
