// Copyright 2025 North Pole Security, Inc.
package utils

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ConfigValidator satisfies the resource.ConfigValidator interface by wrapping
// a function and a simple description.
type ConfigValidator struct {
	description string
	fn          func(context.Context, resource.ValidateConfigRequest, *resource.ValidateConfigResponse)
}

func (v *ConfigValidator) Description(ctx context.Context) string {
	return v.description
}

func (v *ConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.description
}

func (v *ConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	v.fn(ctx, req, resp)
}

func ConfigValidatorFunc(description string, fn func(context.Context, resource.ValidateConfigRequest, *resource.ValidateConfigResponse)) resource.ConfigValidator {
	return &ConfigValidator{
		description: description,
		fn:          fn,
	}
}
