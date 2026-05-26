// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/durationpb"
)

func boolPtrToTF(v *bool) types.Bool {
	if v == nil {
		return types.BoolNull()
	}
	return types.BoolValue(*v)
}

func tfBoolToPtr(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	b := v.ValueBool()
	return &b
}

func stringPtrToTF(v *string) types.String {
	if v == nil {
		return types.StringNull()
	}
	return types.StringValue(*v)
}

func tfStringToPtr(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueString()
	return &s
}

func int32PtrToTFInt64(v *int32) types.Int64 {
	if v == nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64(*v))
}

func tfInt64ToInt32Ptr(v types.Int64) *int32 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	i := int32(v.ValueInt64())
	return &i
}

func uint32PtrToTFInt64(v *uint32) types.Int64 {
	if v == nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64(*v))
}

func tfInt64ToUint32Ptr(v types.Int64) *uint32 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	u := uint32(v.ValueInt64())
	return &u
}

// durationToTFString renders a protobuf duration into Go's duration string form
// (e.g. "30m0s"), or null if the input is nil.
func durationToTFString(d *durationpb.Duration) types.String {
	if d == nil {
		return types.StringNull()
	}
	return types.StringValue(d.AsDuration().String())
}

// tfStringToDuration parses a Terraform string into a protobuf duration. A
// null/unknown value yields (nil, nil). A parse failure yields (nil, error).
func tfStringToDuration(v types.String) (*durationpb.Duration, error) {
	if v.IsNull() || v.IsUnknown() {
		return nil, nil
	}
	s := v.ValueString()
	if s == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, err
	}
	return durationpb.New(d), nil
}
