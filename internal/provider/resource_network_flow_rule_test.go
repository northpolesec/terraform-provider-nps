// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"testing"

	frameworkresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

type fakeNetworkFlowDeleteClient struct {
	svcpb.WorkshopServiceClient
	deleteErr   error
	deleteCalls int
}

func (f *fakeNetworkFlowDeleteClient) DeleteNetworkFlowRule(ctx context.Context, in *apipb.DeleteNetworkFlowRuleRequest, _ ...grpc.CallOption) (*apipb.DeleteNetworkFlowRuleResponse, error) {
	f.deleteCalls++
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return apipb.DeleteNetworkFlowRuleResponse_builder{}.Build(), nil
}

func callNetworkFlowRuleDelete(t *testing.T, r *NetworkFlowRuleResource, model NetworkFlowRuleResourceModel) *frameworkresource.DeleteResponse {
	t.Helper()
	ctx := context.Background()

	var sResp frameworkresource.SchemaResponse
	r.Schema(ctx, frameworkresource.SchemaRequest{}, &sResp)
	req := frameworkresource.DeleteRequest{State: tfsdk.State{Schema: sResp.Schema}}
	if diags := req.State.Set(ctx, model); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	resp := &frameworkresource.DeleteResponse{}
	r.Delete(ctx, req, resp)
	return resp
}

func testNetworkFlowRuleDeleteModel() NetworkFlowRuleResourceModel {
	return NetworkFlowRuleResourceModel{
		Tag:               types.StringValue("global"),
		Name:              types.StringValue("test-rule"),
		Action:            types.StringValue("NETWORK_FLOW_RULE_ACTION_DENY"),
		Direction:         types.StringValue("NETWORK_FLOW_DIRECTION_OUTGOING"),
		Priority:          types.BoolNull(),
		Rank:              types.Int64Null(),
		ProcessCdHashes:   types.ListNull(types.StringType),
		ProcessSigningIds: types.ListNull(types.StringType),
		ProcessTeamIds:    types.ListNull(types.StringType),
		RemoteHostnames:   types.ListNull(types.StringType),
		RemoteDomains:     types.ListNull(types.StringType),
		RemoteAddresses:   types.ListNull(types.StringType),
		Protocols:         types.ListNull(types.Int64Type),
		CustomMsg:         types.StringNull(),
		CustomUrl:         types.StringNull(),
		Comment:           types.StringNull(),
		Ports:             nil,
		Id:                types.Int64Value(42),
	}
}

func TestNetworkFlowRuleDeleteTreatsSupersededIDAsSuccess(t *testing.T) {
	fake := &fakeNetworkFlowDeleteClient{deleteErr: status.Error(codes.InvalidArgument, "rule is superseded")}
	r := &NetworkFlowRuleResource{client: fake}

	resp := callNetworkFlowRuleDelete(t, r, testNetworkFlowRuleDeleteModel())
	if resp.Diagnostics.HasError() {
		t.Fatalf("superseded ID should be an idempotent delete: %v", resp.Diagnostics)
	}
	if fake.deleteCalls != 1 {
		t.Fatalf("DeleteNetworkFlowRule calls = %d, want 1", fake.deleteCalls)
	}
}

func TestAccNetworkFlowRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccNetworkFlowRuleResourceConfig("TestRule1", "global"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "name", "TestRule1"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "tag", "global"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "action", "NETWORK_FLOW_RULE_ACTION_DENY"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "direction", "NETWORK_FLOW_DIRECTION_OUTGOING"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "ports.0.low", "443"),
					resource.TestCheckResourceAttr("nps_workshop_network_flow_rule.test", "ports.0.high", "443"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "nps_workshop_network_flow_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccNetworkFlowRuleResourceConfig(name string, tag string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_network_flow_rule" "test" {
  name      = %[1]q
  tag       = %[2]q
  action    = "NETWORK_FLOW_RULE_ACTION_DENY"
  direction = "NETWORK_FLOW_DIRECTION_OUTGOING"

  process_signing_ids = [
    "EQHXZ8M8AV:com.google.Chrome",
  ]

  remote_domains = [
    "example.com",
  ]

  ports {
    low  = 443
    high = 443
  }

  protocols = [6]
}
`, name, tag)
}
