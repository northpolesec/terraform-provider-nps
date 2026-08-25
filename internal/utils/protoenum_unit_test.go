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

func TestNormalizeEnum(t *testing.T) {
	tests := []struct{ in, prefix, want string }{
		{"HOMEBREW", "PACKAGE_SOURCE_", "PACKAGE_SOURCE_HOMEBREW"},
		{"PACKAGE_SOURCE_HOMEBREW", "PACKAGE_SOURCE_", "PACKAGE_SOURCE_HOMEBREW"},
		{"", "PACKAGE_SOURCE_", ""},
	}
	for _, tt := range tests {
		if got := NormalizeEnum(tt.in, tt.prefix); got != tt.want {
			t.Errorf("NormalizeEnum(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestShortEnum(t *testing.T) {
	tests := []struct{ in, prefix, want string }{
		{"PACKAGE_SOURCE_HOMEBREW", "PACKAGE_SOURCE_", "HOMEBREW"},
		{"HOMEBREW", "PACKAGE_SOURCE_", "HOMEBREW"},
		{"", "PACKAGE_SOURCE_", ""},
	}
	for _, tt := range tests {
		if got := ShortEnum(tt.in, tt.prefix); got != tt.want {
			t.Errorf("ShortEnum(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestMatchEnumForm guards the refresh behavior: Read keeps the spelling the
// state already uses when the value is unchanged, so upgrades never print
// "changed outside of Terraform" over spelling alone. New values (imports,
// list results, real changes) come back in the short canonical form.
func TestMatchEnumForm(t *testing.T) {
	tests := []struct{ name, prior, fresh, want string }{
		{"long prior keeps long", "PACKAGE_SOURCE_HOMEBREW", "PACKAGE_SOURCE_HOMEBREW", "PACKAGE_SOURCE_HOMEBREW"},
		{"short prior keeps short", "HOMEBREW", "PACKAGE_SOURCE_HOMEBREW", "HOMEBREW"},
		{"empty prior (import) goes short", "", "PACKAGE_SOURCE_HOMEBREW", "HOMEBREW"},
		{"real change goes short", "NPM", "PACKAGE_SOURCE_HOMEBREW", "HOMEBREW"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchEnumForm(tt.prior, tt.fresh, "PACKAGE_SOURCE_"); got != tt.want {
				t.Errorf("MatchEnumForm(%q, %q) = %q, want %q", tt.prior, tt.fresh, got, tt.want)
			}
		})
	}
}

func TestProtoEnumPrefixedValueLists(t *testing.T) {
	enum := apipb.PackageSource(0).Descriptor()
	long := ProtoEnumValidValues(enum)
	short := ProtoEnumShortValues(enum, "PACKAGE_SOURCE_")
	accepted := ProtoEnumAcceptedValues(enum, "PACKAGE_SOURCE_")

	if len(short) != len(long) {
		t.Fatalf("short list len = %d, want %d", len(short), len(long))
	}
	if !slices.Contains(short, "HOMEBREW") || slices.Contains(short, "PACKAGE_SOURCE_HOMEBREW") {
		t.Errorf("short values = %v, want bare names only", short)
	}
	if len(accepted) != 2*len(long) {
		t.Fatalf("accepted list len = %d, want %d", len(accepted), 2*len(long))
	}
	if !slices.Contains(accepted, "HOMEBREW") || !slices.Contains(accepted, "PACKAGE_SOURCE_HOMEBREW") {
		t.Errorf("accepted values = %v, want both spellings", accepted)
	}
}
