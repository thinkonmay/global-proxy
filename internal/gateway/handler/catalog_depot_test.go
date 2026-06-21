package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestGetStoreDepotKeysSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_depotkey" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"570":"depot-key"}`))
	}))
	defer srv.Close()

	h := NewCatalogHandler(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/catalog/stores/570/depot-keys", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var keys map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	if keys["570"] != "depot-key" {
		t.Fatalf("keys: %v", keys)
	}
}

func TestGetStoreDepotKeysInvalidID(t *testing.T) {
	h := NewCatalogHandler(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"}))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/catalog/stores/abc/depot-keys", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
