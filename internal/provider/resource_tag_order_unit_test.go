// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func tagOrderValue(t *testing.T, count int) types.List {
	t.Helper()
	ctx := context.Background()
	tags := make([]string, count)
	for i := range tags {
		tags[i] = fmt.Sprintf("tag-%02d", i)
	}
	value, diags := types.ListValueFrom(ctx, types.StringType, tags)
	if diags.HasError() {
		t.Fatalf("building tags list: %v", diags)
	}
	return value
}

func TestConfiguredTagOrderMaxSize(t *testing.T) {
	if got := configuredTagOrderMaxSize(types.Int64Null()); got != 25 {
		t.Fatalf("default max size = %d, want 25", got)
	}
	if got := configuredTagOrderMaxSize(types.Int64Value(40)); got != 40 {
		t.Fatalf("configured max size = %d, want 40", got)
	}
}

func TestTagOrderSizeUsesDefaultLimit(t *testing.T) {
	var diags diag.Diagnostics
	validateTagOrderSize(tagOrderValue(t, 26), (&TagOrderResource{}).effectiveMaxSize(), &diags)
	if !diags.HasError() {
		t.Fatal("expected 26 tags to exceed the default limit of 25")
	}
}

func TestTagOrderSizeAcceptsConfiguredLimit(t *testing.T) {
	var diags diag.Diagnostics
	validateTagOrderSize(tagOrderValue(t, 26), 26, &diags)
	if diags.HasError() {
		t.Fatalf("26 tags should be accepted with tag_order_max_size=26: %v", diags)
	}
}
