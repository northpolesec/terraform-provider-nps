// Copyright 2025 North Pole Security, Inc.
package utils

import (
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
