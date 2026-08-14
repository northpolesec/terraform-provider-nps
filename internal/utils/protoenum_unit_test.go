// Copyright 2025 North Pole Security, Inc.
package utils

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// TestProtoEnumValidValuesExcludesSentinel guards the fix for validators
// accepting the protobuf zero value (e.g. POLICY_UNKNOWN) as valid Terraform
// configuration: the zero value must never appear in the returned list, every
// other declared value must, and the length must track the enum 1:1 minus
// the sentinel.
func TestProtoEnumValidValuesExcludesSentinel(t *testing.T) {
	tests := []struct {
		name      string
		enum      protoreflect.EnumDescriptor
		sentinel  string
		wantValue string
	}{
		{
			name:      "Policy",
			enum:      apipb.Policy(0).Descriptor(),
			sentinel:  "POLICY_UNKNOWN",
			wantValue: "ALLOWLIST",
		},
		{
			name:      "PackageSource",
			enum:      apipb.PackageSource(0).Descriptor(),
			sentinel:  "PACKAGE_SOURCE_UNSPECIFIED",
			wantValue: "PACKAGE_SOURCE_HOMEBREW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProtoEnumValidValues(tt.enum)

			if slices.Contains(got, tt.sentinel) {
				t.Errorf("ProtoEnumValidValues(%s) contains sentinel %q, want it excluded", tt.name, tt.sentinel)
			}
			if !slices.Contains(got, tt.wantValue) {
				t.Errorf("ProtoEnumValidValues(%s) = %v, want it to contain %q", tt.name, got, tt.wantValue)
			}
			if want := tt.enum.Values().Len() - 1; len(got) != want {
				t.Errorf("ProtoEnumValidValues(%s) len = %d, want %d (declared values minus the sentinel)", tt.name, len(got), want)
			}
		})
	}
}
