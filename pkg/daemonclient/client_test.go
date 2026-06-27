package daemonclient_test

import (
	"context"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/daemonclient"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestNewRequiresVault(t *testing.T) {
	_, err := daemonclient.New(context.Background(), daemonclient.Config{}, postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"}))
	if err == nil {
		t.Fatal("expected error without vault config")
	}
}
