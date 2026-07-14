// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// isDeleteNoOp reports whether a delete error means the remote object is
// already absent.
func isDeleteNoOp(err error) bool {
	return status.Code(err) == codes.NotFound
}

// isRuleDeleteNoOp also accepts Workshop's terminal response for a stale rule
// identifier after an upsert. Keep this rule-specific so unrelated resource
// types cannot mask an InvalidArgument response that happens to share text.
func isRuleDeleteNoOp(err error) bool {
	return isDeleteNoOp(err) ||
		(status.Code(err) == codes.InvalidArgument && strings.Contains(status.Convert(err).Message(), "rule is superseded"))
}
