package utils

import "google.golang.org/protobuf/reflect/protoreflect"

func ProtoEnumToList(enum protoreflect.EnumDescriptor) []string {
	values := enum.Values()

	list := make([]string, 0, values.Len())

	for i := 0; i < values.Len(); i++ {
		value := values.Get(i)
		list = append(list, string(value.Name()))
	}

	return list
}
