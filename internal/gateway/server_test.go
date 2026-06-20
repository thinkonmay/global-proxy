package main

import (
	"net/http"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestStartServersPlainHTTP(t *testing.T) {
	cfg := &config.Config{
		Port: "0",
		TLS:  config.TLS{Enabled: false},
	}
	servers, errCh, err := startServers(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = servers.shutdown(t.Context()) }()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	default:
	}
}

func TestStartTLSServersRequiresHosts(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLS{Enabled: true},
	}
	_, _, err := startTLSServers(cfg, http.NotFoundHandler())
	if err == nil {
		t.Fatal("expected error when tls hosts empty")
	}
}
