package certmanager

import (
	"testing"
)

func TestNewRequiresHosts(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty hosts")
	}
}

func TestNewDefaultsCacheDir(t *testing.T) {
	m, err := New(Config{Hosts: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || m.TLSConfig() == nil {
		t.Fatal("expected TLS config")
	}
}
