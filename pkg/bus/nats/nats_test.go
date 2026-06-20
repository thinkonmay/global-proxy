package busnats

import "testing"

func TestStreamNameSanitizesTopic(t *testing.T) {
	cases := map[string]string{
		"jobs.volume":     "jobs_volume",
		"usage.snapshot":  "usage_snapshot",
		"wild*card":       "wild_card",
		"has space":       "has_space",
	}
	for in, want := range cases {
		if got := streamName(in); got != want {
			t.Fatalf("streamName(%q) = %q, want %q", in, got, want)
		}
	}
}
