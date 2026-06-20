package main

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestStartMetricsServerDisabledWithoutSecret(t *testing.T) {
	cache, srv, errCh, err := startMetricsServer(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if cache != nil || srv != nil || errCh != nil {
		t.Fatalf("expected nil metrics server when ingest secret empty, got cache=%v srv=%v errCh=%v", cache, srv, errCh)
	}
}
