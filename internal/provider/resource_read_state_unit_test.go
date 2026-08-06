// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestClearFileAccessRuleOptionalState(t *testing.T) {
	data := FileAccessRuleResourceModel{
		BlockMessage:              types.StringValue("stale"),
		EventDetailUrl:            types.StringValue("https://example.com"),
		EventDetailText:           types.StringValue("stale"),
		PathLiterals:              types.ListValueMust(types.StringType, []attr.Value{types.StringValue("/stale")}),
		PathPrefixes:              types.ListValueMust(types.StringType, []attr.Value{types.StringValue("/stale")}),
		ProcessBinaryPaths:        types.ListValueMust(types.StringType, []attr.Value{types.StringValue("/stale")}),
		ProcessCdHashes:           types.ListValueMust(types.StringType, []attr.Value{types.StringValue("stale")}),
		ProcessSigningIds:         types.ListValueMust(types.StringType, []attr.Value{types.StringValue("stale")}),
		ProcessCertificateSha256s: types.ListValueMust(types.StringType, []attr.Value{types.StringValue("stale")}),
		ProcessTeamIds:            types.ListValueMust(types.StringType, []attr.Value{types.StringValue("stale")}),
	}

	clearFileAccessRuleOptionalState(&data)

	if !data.BlockMessage.IsNull() || !data.EventDetailUrl.IsNull() || !data.EventDetailText.IsNull() {
		t.Fatal("string optionals retained stale state")
	}
	if !data.PathLiterals.IsNull() || !data.PathPrefixes.IsNull() ||
		!data.ProcessBinaryPaths.IsNull() || !data.ProcessCdHashes.IsNull() ||
		!data.ProcessSigningIds.IsNull() || !data.ProcessCertificateSha256s.IsNull() ||
		!data.ProcessTeamIds.IsNull() {
		t.Fatal("list optionals retained stale state")
	}
}

func TestClearFileAccessRuleOptionalStatePreservesKnownEmpty(t *testing.T) {
	emptyStrings := types.ListValueMust(types.StringType, []attr.Value{})
	data := FileAccessRuleResourceModel{
		BlockMessage:              types.StringValue(""),
		EventDetailUrl:            types.StringValue(""),
		EventDetailText:           types.StringValue(""),
		PathLiterals:              emptyStrings,
		PathPrefixes:              emptyStrings,
		ProcessBinaryPaths:        emptyStrings,
		ProcessCdHashes:           emptyStrings,
		ProcessSigningIds:         emptyStrings,
		ProcessCertificateSha256s: emptyStrings,
		ProcessTeamIds:            emptyStrings,
	}

	clearFileAccessRuleOptionalState(&data)

	if data.BlockMessage.IsNull() || data.EventDetailUrl.IsNull() || data.EventDetailText.IsNull() {
		t.Fatal("explicit empty strings were normalized to null")
	}
	if data.PathLiterals.IsNull() || data.PathPrefixes.IsNull() ||
		data.ProcessBinaryPaths.IsNull() || data.ProcessCdHashes.IsNull() ||
		data.ProcessSigningIds.IsNull() || data.ProcessCertificateSha256s.IsNull() ||
		data.ProcessTeamIds.IsNull() {
		t.Fatal("explicit empty lists were normalized to null")
	}
}

func TestClearPackageRuleOptionalState(t *testing.T) {
	data := PackageRuleResourceModel{
		MinDate:       types.StringValue("2026-01-01T00:00:00Z"),
		MaxDate:       types.StringValue("2026-12-31T00:00:00Z"),
		VersionRegexp: types.StringValue("stale"),
	}

	clearPackageRuleOptionalState(&data)

	if !data.MinDate.IsNull() || !data.MaxDate.IsNull() || !data.VersionRegexp.IsNull() {
		t.Fatal("package rule optionals retained stale state")
	}
}

func TestClearPackageRuleOptionalStatePreservesKnownEmpty(t *testing.T) {
	data := PackageRuleResourceModel{
		MinDate:       types.StringValue(""),
		MaxDate:       types.StringValue(""),
		VersionRegexp: types.StringValue(""),
	}

	clearPackageRuleOptionalState(&data)

	if data.MinDate.IsNull() || data.MaxDate.IsNull() || data.VersionRegexp.IsNull() {
		t.Fatal("explicit empty package rule strings were normalized to null")
	}
}

func TestClearRuleOptionalStateIncludingBlockReason(t *testing.T) {
	data := RuleResourceModel{
		BlockReason: types.StringValue("BLOCK_REASON_MALICIOUS"),
		Comment:     types.StringValue("stale"),
		CustomMsg:   types.StringValue("stale"),
		CustomURL:   types.StringValue("https://example.com"),
		CELExpr:     types.StringValue("target.path == '/stale'"),
	}

	clearRuleOptionalState(&data)

	if !data.BlockReason.IsNull() {
		t.Fatal("block_reason retained stale state")
	}
	if !data.Comment.IsNull() || !data.CustomMsg.IsNull() || !data.CustomURL.IsNull() || !data.CELExpr.IsNull() {
		t.Fatal("rule optionals retained stale state")
	}
}

func TestClearRuleOptionalStatePreservesKnownEmpty(t *testing.T) {
	data := RuleResourceModel{
		BlockReason: types.StringValue(""),
		Comment:     types.StringValue(""),
		CustomMsg:   types.StringValue(""),
		CustomURL:   types.StringValue(""),
		CELExpr:     types.StringValue(""),
	}

	clearRuleOptionalState(&data)

	if data.BlockReason.IsNull() || data.Comment.IsNull() || data.CustomMsg.IsNull() ||
		data.CustomURL.IsNull() || data.CELExpr.IsNull() {
		t.Fatal("explicit empty rule strings were normalized to null")
	}
}

func TestClearSignalOptionalState(t *testing.T) {
	data := SignalResourceModel{
		Description: types.StringValue("stale"),
		Labels: types.SetValueMust(
			types.StringType,
			[]attr.Value{types.StringValue("stale")},
		),
	}

	clearSignalOptionalState(&data)

	if !data.Description.IsNull() || !data.Labels.IsNull() {
		t.Fatal("signal optionals retained stale state")
	}
}

func TestClearSignalOptionalStatePreservesKnownEmpty(t *testing.T) {
	data := SignalResourceModel{
		Description: types.StringValue(""),
		Labels:      types.SetValueMust(types.StringType, []attr.Value{}),
	}

	clearSignalOptionalState(&data)

	if data.Description.IsNull() || data.Labels.IsNull() {
		t.Fatal("explicit empty signal values were normalized to null")
	}
}

func TestClearNetworkFlowRuleOptionalState(t *testing.T) {
	stringValues := types.ListValueMust(
		types.StringType,
		[]attr.Value{types.StringValue("stale")},
	)
	data := NetworkFlowRuleResourceModel{
		ProcessCdHashes:   stringValues,
		ProcessSigningIds: stringValues,
		ProcessTeamIds:    stringValues,
		RemoteHostnames:   stringValues,
		RemoteDomains:     stringValues,
		RemoteAddresses:   stringValues,
		Protocols: types.ListValueMust(
			types.Int64Type,
			[]attr.Value{types.Int64Value(6)},
		),
		CustomMsg: types.StringValue("stale"),
		CustomUrl: types.StringValue("https://example.com"),
		Comment:   types.StringValue("stale"),
		Ports: []NetworkFlowRulePortRangeModel{
			{Low: types.Int64Value(443)},
		},
	}

	clearNetworkFlowRuleOptionalState(&data)

	if !data.ProcessCdHashes.IsNull() || !data.ProcessSigningIds.IsNull() ||
		!data.ProcessTeamIds.IsNull() || !data.RemoteHostnames.IsNull() ||
		!data.RemoteDomains.IsNull() || !data.RemoteAddresses.IsNull() ||
		!data.Protocols.IsNull() {
		t.Fatal("network flow list optionals retained stale state")
	}
	if !data.CustomMsg.IsNull() || !data.CustomUrl.IsNull() || !data.Comment.IsNull() {
		t.Fatal("network flow string optionals retained stale state")
	}
	if data.Ports != nil {
		t.Fatal("network flow ports retained stale state")
	}
}

func TestClearNetworkFlowRuleOptionalStatePreservesKnownEmpty(t *testing.T) {
	emptyStrings := types.ListValueMust(types.StringType, []attr.Value{})
	data := NetworkFlowRuleResourceModel{
		ProcessCdHashes:   emptyStrings,
		ProcessSigningIds: emptyStrings,
		ProcessTeamIds:    emptyStrings,
		RemoteHostnames:   emptyStrings,
		RemoteDomains:     emptyStrings,
		RemoteAddresses:   emptyStrings,
		Protocols:         types.ListValueMust(types.Int64Type, []attr.Value{}),
		CustomMsg:         types.StringValue(""),
		CustomUrl:         types.StringValue(""),
		Comment:           types.StringValue(""),
		Ports:             []NetworkFlowRulePortRangeModel{},
	}

	clearNetworkFlowRuleOptionalState(&data)

	if data.ProcessCdHashes.IsNull() || data.ProcessSigningIds.IsNull() ||
		data.ProcessTeamIds.IsNull() || data.RemoteHostnames.IsNull() ||
		data.RemoteDomains.IsNull() || data.RemoteAddresses.IsNull() ||
		data.Protocols.IsNull() {
		t.Fatal("explicit empty network flow lists were normalized to null")
	}
	if data.CustomMsg.IsNull() || data.CustomUrl.IsNull() || data.Comment.IsNull() {
		t.Fatal("explicit empty network flow strings were normalized to null")
	}
	if data.Ports == nil || len(data.Ports) != 0 {
		t.Fatal("explicit empty network flow ports were normalized to null")
	}
}

func TestNetworkFlowRulePortsFromProtoClearsStaleHigh(t *testing.T) {
	prior := []NetworkFlowRulePortRangeModel{{
		Low:  types.Int64Value(443),
		High: types.Int64Value(8443),
	}}
	ports := []*apipb.NetworkFlowRule_PortRange{
		apipb.NetworkFlowRule_PortRange_builder{Low: 443}.Build(),
	}

	got := networkFlowRulePortsFromProto(prior, ports)

	if len(got) != 1 {
		t.Fatalf("ports length = %d, want 1", len(got))
	}
	if !got[0].High.IsNull() {
		t.Fatalf("stale high = %v, want null", got[0].High)
	}
}

func TestNetworkFlowRulePortsFromProtoPreservesExplicitZeroHigh(t *testing.T) {
	prior := []NetworkFlowRulePortRangeModel{{
		Low:  types.Int64Value(443),
		High: types.Int64Value(0),
	}}
	ports := []*apipb.NetworkFlowRule_PortRange{
		apipb.NetworkFlowRule_PortRange_builder{Low: 443}.Build(),
	}

	got := networkFlowRulePortsFromProto(prior, ports)

	if len(got) != 1 {
		t.Fatalf("ports length = %d, want 1", len(got))
	}
	if got[0].High.IsNull() || got[0].High.ValueInt64() != 0 {
		t.Fatalf("explicit high = %v, want known zero", got[0].High)
	}
}

func TestSetTagGroupReferenceStateWhenRemoteEmpty(t *testing.T) {
	tests := []struct {
		name     string
		prior    types.Set
		wantNull bool
	}{
		{
			name:     "prior null remains null",
			prior:    types.SetNull(types.StringType),
			wantNull: true,
		},
		{
			name:  "known empty remains known empty",
			prior: types.SetValueMust(types.StringType, []attr.Value{}),
		},
		{
			name: "stale nonempty becomes null",
			prior: types.SetValueMust(
				types.StringType,
				[]attr.Value{types.StringValue("stale")},
			),
			wantNull: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := TagResourceModel{
				GroupNames:  tt.prior,
				GroupIdpIds: tt.prior,
			}
			var diags diag.Diagnostics

			setTagGroupReferenceState(context.Background(), &data, nil, nil, &diags)

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			for field, got := range map[string]types.Set{
				"group_names":   data.GroupNames,
				"group_idp_ids": data.GroupIdpIds,
			} {
				if got.IsNull() != tt.wantNull {
					t.Errorf("%s null = %v, want %v", field, got.IsNull(), tt.wantNull)
				}
				if !tt.wantNull && len(got.Elements()) != 0 {
					t.Errorf("%s has %d elements, want known empty", field, len(got.Elements()))
				}
			}
		})
	}
}
