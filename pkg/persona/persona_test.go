package persona_test

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/persona"
)

func TestNormalizeGameName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{" Elden Ring ", "elden ring"},
		{"game.exe", "game"},
	}
	for _, tc := range tests {
		if got := persona.NormalizeGameNameForTest(tc.in); got != tc.want {
			t.Fatalf("normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBestSteamMatch(t *testing.T) {
	hits := []persona.SteamHitForTest{
		{ID: 1, Name: "Other Game"},
		{ID: 2, Name: "Elden Ring"},
	}
	id, ok := persona.BestSteamMatchForTest(hits, "Elden Ring")
	if !ok || id != 2 {
		t.Fatalf("match = (%d, %v)", id, ok)
	}
}

func TestPersonaResponseSchemaRequired(t *testing.T) {
	schema := persona.ResponseSchemaForTest()
	required, _ := schema["required"].([]string)
	if len(required) != 3 {
		t.Fatalf("required = %v", required)
	}
}
