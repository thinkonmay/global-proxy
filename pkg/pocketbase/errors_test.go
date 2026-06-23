package pocketbase

import (
	"errors"
	"testing"
)

func TestErrUnknownIssuer(t *testing.T) {
	if !errors.Is(ErrUnknownIssuer, ErrUnknownIssuer) {
		t.Fatal("ErrUnknownIssuer should match itself")
	}
	if ErrUnknownIssuer.Error() != "unknown cluster issuer" {
		t.Fatalf("message = %q", ErrUnknownIssuer.Error())
	}
}
