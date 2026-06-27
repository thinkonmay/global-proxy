package main

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

// NewHandler is pure composition: it must wire every per-domain subscriber so
// the worker entrypoint can call Init/Start without nil panics. Construction is
// dependency-free (sub-constructors only stash their args), so nil deps are
// enough to exercise the wiring.
func TestNewHandlerWiresAllDomains(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, &config.Config{})
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if h.volume == nil {
		t.Error("volume handler not wired")
	}
	if h.payment == nil {
		t.Error("payment handler not wired")
	}
	if h.usage == nil {
		t.Error("usage handler not wired")
	}
	if h.persona == nil {
		t.Error("persona handler not wired")
	}
	if h.mail == nil {
		t.Error("mail handler not wired")
	}
}
