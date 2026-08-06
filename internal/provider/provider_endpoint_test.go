// Copyright 2026 North Pole Security, Inc.
package provider

import "testing"

func TestResolveEndpointPrecedence(t *testing.T) {
	t.Setenv("WORKSHOP_ENDPOINT", "workshop.example")
	t.Setenv("NPS_ENDPOINT", "legacy.example")

	endpoint, deprecated := resolveEndpoint("configured.example")
	if endpoint != "configured.example" || deprecated {
		t.Fatalf("resolveEndpoint(configured) = %q, %v", endpoint, deprecated)
	}

	endpoint, deprecated = resolveEndpoint("")
	if endpoint != "workshop.example" || deprecated {
		t.Fatalf("resolveEndpoint(WORKSHOP_ENDPOINT) = %q, %v", endpoint, deprecated)
	}
}

func TestResolveEndpointDeprecatedFallback(t *testing.T) {
	t.Setenv("WORKSHOP_ENDPOINT", "")
	t.Setenv("NPS_ENDPOINT", "legacy.example")

	endpoint, deprecated := resolveEndpoint("")
	if endpoint != "legacy.example" || !deprecated {
		t.Fatalf("resolveEndpoint(NPS_ENDPOINT) = %q, %v", endpoint, deprecated)
	}
}

func TestResolveEndpointMissing(t *testing.T) {
	t.Setenv("WORKSHOP_ENDPOINT", "")
	t.Setenv("NPS_ENDPOINT", "")

	endpoint, deprecated := resolveEndpoint("")
	if endpoint != "" || deprecated {
		t.Fatalf("resolveEndpoint(missing) = %q, %v", endpoint, deprecated)
	}
}
