package vaultpki_test

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/vaultpki"
)

func TestReloadableStoreAndClientTLS(t *testing.T) {
	// Minimal self-signed material is not needed — test nil path returns insecure opts.
	opts, err := vaultpki.GrpcDialOptions(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) == 0 {
		t.Fatal("expected dial options")
	}
	r := vaultpki.NewReloadable()
	if r.Material() != nil {
		t.Fatal("expected nil material")
	}
}
