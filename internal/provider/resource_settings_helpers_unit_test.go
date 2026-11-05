// Copyright 2026 North Pole Security, Inc.
package provider

import "testing"

func TestTagNameRegex(t *testing.T) {
	for _, c := range []struct {
		tag  string
		want bool
	}{
		{"global", true},
		{"host:DF6A09A0-3F91-47BB-AD4D-DD2105A4F4E9", true},
		{"eng_team.v2", true},
		{"Équipe", true},
		{"eng team", true},
		{"eng team 2", true},
		{"", false},
		{" eng", false},
		{"eng ", false},
		{"eng  team", false},
		{"eng\tteam", false},
		{`eng"team`, false},
		{"eng/team", false},
		{"eng%", false},
	} {
		if got := tagNameRegex.MatchString(c.tag); got != c.want {
			t.Errorf("tagNameRegex.MatchString(%q) = %v, want %v", c.tag, got, c.want)
		}
	}
}
