package catalog

import "testing"

func TestSanitizeCodeName(t *testing.T) {
	if got := sanitizeCodeName("  Hello World!! "); got != "hello_world" {
		t.Fatalf("got %q", got)
	}
}
