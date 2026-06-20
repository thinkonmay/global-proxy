package rpc

import (
	"encoding/hex"
	"testing"
)

func TestPasswordL2Deterministic(t *testing.T) {
	a := PasswordL2("secret")
	b := PasswordL2("secret")
	if a != b {
		t.Fatal("PasswordL2 should be deterministic")
	}
	if len(a) != hex.EncodedLen(64) {
		t.Fatalf("unexpected hash length: %d", len(a))
	}
}

func TestDecryptJSONWrongPassword(t *testing.T) {
	wire, err := EncryptJSON(map[string]string{"k": "v"}, PasswordL2("good"))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := DecryptJSON(wire, PasswordL2("bad"), &out); err == nil {
		t.Fatal("expected decrypt failure with wrong password")
	}
}
