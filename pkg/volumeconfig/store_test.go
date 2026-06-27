package volumeconfig_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/volumeconfig"
)

func TestPatchConfiguration(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/patch_volume_configuration_v1") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	err := volumeconfig.Patch(context.Background(), pr, "u@example.com", "550e8400-e29b-41d4-a716-446655440000", map[string]any{
		"assistant": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["email"] != "u@example.com" {
		t.Fatalf("email: %v", got["email"])
	}
}

func TestTransientEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/lookup_volume_configuration_v1") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"transient": true})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	ok, err := volumeconfig.TransientEnabled(context.Background(), pr, "u@example.com", "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected transient")
	}
}
