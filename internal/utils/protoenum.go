// Copyright 2025 North Pole Security, Inc.
package utils

import (
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ProtoEnumToList converts a protobuf enum descriptor to a list of strings.
func ProtoEnumToList(enum protoreflect.EnumDescriptor) []string {
	values := enum.Values()

	list := make([]string, 0, values.Len())

	for i := 0; i < values.Len(); i++ {
		value := values.Get(i)
		list = append(list, string(value.Name()))
	}

	return list
}
