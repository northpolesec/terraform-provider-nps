// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeleteNoOpClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         error
		wantGeneric bool
		wantRule    bool
	}{
		{name: "not found", err: status.Error(codes.NotFound, "gone"), wantGeneric: true, wantRule: true},
		{name: "superseded rule", err: status.Error(codes.InvalidArgument, "invalid argument: rule is superseded"), wantRule: true},
		{name: "unrelated invalid argument", err: status.Error(codes.InvalidArgument, "bad input")},
		{name: "permission denied", err: status.Error(codes.PermissionDenied, "no")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDeleteNoOp(tt.err); got != tt.wantGeneric {
				t.Fatalf("isDeleteNoOp(%v) = %v, want %v", tt.err, got, tt.wantGeneric)
			}
			if got := isRuleDeleteNoOp(tt.err); got != tt.wantRule {
				t.Fatalf("isRuleDeleteNoOp(%v) = %v, want %v", tt.err, got, tt.wantRule)
			}
		})
	}
}
