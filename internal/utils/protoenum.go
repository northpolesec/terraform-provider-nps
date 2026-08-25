// Copyright 2025 North Pole Security, Inc.
package utils

import (
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// ProtoEnumValidValues converts a protobuf enum descriptor to a list of
// strings, one per declared value. The zero value is always excluded: by
// protobuf convention it is the enum's unspecified/unknown sentinel, and it
// is never valid Terraform configuration.
func ProtoEnumValidValues(enum protoreflect.EnumDescriptor) []string {
	values := enum.Values()

	list := make([]string, 0, values.Len()-1)

	for i := range values.Len() {
		if values.Get(i).Number() == 0 {
			continue
		}
		list = append(list, string(values.Get(i).Name()))
	}

	return list
}

// NormalizeEnum returns the full proto name for s, adding prefix when it is
// absent. The empty string passes through so null/unset model values never
// grow a prefix.
func NormalizeEnum(s, prefix string) string {
	if s == "" || strings.HasPrefix(s, prefix) {
		return s
	}
	return prefix + s
}

// ShortEnum strips prefix from s, returning the bare spelling.
func ShortEnum(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}

// MatchEnumForm returns fresh in the spelling prior already uses when both
// name the same enum value, and the short canonical spelling otherwise. Read
// paths use it so a refresh never rewrites state over spelling alone.
func MatchEnumForm(prior, fresh, prefix string) string {
	if NormalizeEnum(prior, prefix) == fresh {
		return prior
	}
	return ShortEnum(fresh, prefix)
}

// ProtoEnumShortValues is ProtoEnumValidValues with prefix stripped from
// every name: the canonical spellings for documentation.
func ProtoEnumShortValues(enum protoreflect.EnumDescriptor, prefix string) []string {
	long := ProtoEnumValidValues(enum)
	short := make([]string, len(long))
	for i, v := range long {
		short[i] = ShortEnum(v, prefix)
	}
	return short
}

// ProtoEnumAcceptedValues returns the short spellings followed by the long
// proto names: everything a validator accepts during the deprecation window
// for the prefixed spellings.
func ProtoEnumAcceptedValues(enum protoreflect.EnumDescriptor, prefix string) []string {
	return append(ProtoEnumShortValues(enum, prefix), ProtoEnumValidValues(enum)...)
}
