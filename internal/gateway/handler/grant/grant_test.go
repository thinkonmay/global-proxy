package grant

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestStorageGrantSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/grant_bucket_access_v1" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"bucket_name": "test-bucket"})
	}))
	defer srv.Close()

	h := New(config.Config{}, postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/storage/grant?email=u@example.com&cluster=node1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var cred map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&cred); err != nil {
		t.Fatal(err)
	}
	if cred["bucket_name"] != "test-bucket" {
		t.Fatalf("cred: %v", cred)
	}
}

func TestStorageGrantMissingParams(t *testing.T) {
	h := New(config.Config{}, postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"}), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/storage/grant?email=u@example.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestStorageGrantGlobalUnavailable(t *testing.T) {
	h := New(config.Config{}, postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"}), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/storage/grant?email=u@example.com&cluster=node1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}
