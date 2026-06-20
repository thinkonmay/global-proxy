package cluster

import (
	"encoding/json"
	"testing"
)

func TestParseSecret(t *testing.T) {
	raw, _ := json.Marshal(Secret{
		URL:      "https://pb.example.com/",
		Username: " admin ",
		Password: "secret",
	})
	got, err := ParseSecret(raw)
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	if got.URL != "https://pb.example.com" {
		t.Errorf("URL = %q, want trimmed base", got.URL)
	}
	if got.Username != "admin" {
		t.Errorf("Username = %q, want admin", got.Username)
	}
}

func TestParseSecretRejectsIncomplete(t *testing.T) {
	_, err := ParseSecret(json.RawMessage(`{"url":"https://x"}`))
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}
