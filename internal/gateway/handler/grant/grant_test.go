package grant

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/testsupport"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestStorageGrantSuccess(t *testing.T) {
	const secret = "grant-test-secret"
	auth.ConfigureGoTrueAuth(secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/get_subscription_v3":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"cluster": "node1.thinkmay.net"},
			})
		case "/rpc/grant_bucket_access_v1":
			_ = json.NewEncoder(w).Encode(map[string]any{"bucket_name": "test-bucket"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	h := New(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/storage/grant", nil)
	req.Header.Set("Authorization", "Bearer "+testsupport.GoTrueJWT(t, secret, "u1", "u@example.com"))
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

func TestStorageGrantMissingAuth(t *testing.T) {
	h := New(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"}), nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/storage/grant", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestStorageGrantGlobalUnavailable(t *testing.T) {
	const secret = "grant-test-secret"
	auth.ConfigureGoTrueAuth(secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/get_subscription_v3":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"cluster": "node1.thinkmay.net"},
			})
		case "/rpc/grant_bucket_access_v1":
			http.Error(w, "busy", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	h := New(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/storage/grant", nil)
	req.Header.Set("Authorization", "Bearer "+testsupport.GoTrueJWT(t, secret, "u1", "u@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}
