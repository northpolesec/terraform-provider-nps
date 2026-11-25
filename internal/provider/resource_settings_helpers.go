// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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

func priorHeaderValue(i int, headers []*apipb.HTTPHeader, prior types.List) types.String {
	key := headers[i].GetKey()
	occurrence := 0
	for _, h := range headers[:i] {
		if strings.EqualFold(key, h.GetKey()) {
			occurrence++
		}
	}
	for _, element := range prior.Elements() {
		header := element.(types.Object)
		if strings.EqualFold(key, priorString(header, "key").ValueString()) {
			if occurrence == 0 {
				return priorString(header, "value")
			}
			occurrence--
		}
	}
	return types.StringNull()
}

func writeOnlySecretAttribute(plain, version string) schema.StringAttribute {
	const text = "Write-only %s. Not stored in state. Change %s to send a new value. Needs Terraform 1.11+."
	return schema.StringAttribute{
		Description:         fmt.Sprintf(text, plain, version),
		MarkdownDescription: fmt.Sprintf(text, "`"+plain+"`", "`"+version+"`"),
		Optional:            true,
		Sensitive:           true,
		WriteOnly:           true,
		Validators:          []validator.String{stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName(plain))},
	}
}

func writeOnlyVersionAttribute(attributes string) schema.StringAttribute {
	const text = "Change this value to send %s. A version change cannot clear a secret, and import cannot recover one."
	return schema.StringAttribute{
		Description:         fmt.Sprintf(text, strings.ReplaceAll(attributes, "`", "")),
		MarkdownDescription: fmt.Sprintf(text, attributes),
		Optional:            true,
	}
}

func headerValueAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		Description:         "HTTP header value. Stored in state. Set exactly one of value or value_wo.",
		MarkdownDescription: "HTTP header value. Stored in state. Set exactly one of `value` or `value_wo`.",
		Optional:            true,
		Sensitive:           true,
		DeprecationMessage:  "Use value_wo.",
		Validators:          []validator.String{stringvalidator.AtLeastOneOf(path.MatchRelative().AtParent().AtName("value_wo"))},
	}
}

func withWriteOnly(value *string, wo types.String) *string {
	if wo.IsNull() || wo.IsUnknown() {
		return value
	}
	return tfStringToPtr(wo)
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

// tagNameRegex and tagNameMaxLen mirror the server-side tag validation
// (letters, digits, single interior spaces, '.', ':', '-', '_', max 42
// characters). Enforcing them in the provider gives early feedback and ensures
// a tag cannot break out of the filter string it is interpolated into.
var tagNameRegex = regexp.MustCompile(`^[\p{L}\p{N}.:_-]+( [\p{L}\p{N}.:_-]+)*$`)

const (
	tagNameMaxLen = 42

	tagNameRegexMessage = "must contain only letters, digits, spaces, periods, colons, hyphens, and underscores, and must not start or end with a space or contain consecutive spaces"
)
