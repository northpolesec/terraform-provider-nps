// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
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

// int32sToTFInt64Set builds a set of Int64 from a repeated int32 proto field,
// returning a null set (rather than an empty one) when there are no values so
// it matches an unset attribute.
func int32sToTFInt64Set(ctx context.Context, values []int32, diags *diag.Diagnostics) types.Set {
	if len(values) == 0 {
		return types.SetNull(types.Int64Type)
	}
	out := make([]int64, 0, len(values))
	for _, v := range values {
		out = append(out, int64(v))
	}
	set, d := types.SetValueFrom(ctx, types.Int64Type, out)
	diags.Append(d...)
	return set
}

// tfInt64SetToInt32s converts a set of Int64 to a repeated int32 proto field.
func tfInt64SetToInt32s(ctx context.Context, set types.Set, diags *diag.Diagnostics) []int32 {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	var values []int64
	diags.Append(set.ElementsAs(ctx, &values, false)...)
	out := make([]int32, 0, len(values))
	for _, v := range values {
		out = append(out, int32(v))
	}
	return out
}
