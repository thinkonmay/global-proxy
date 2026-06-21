package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestBillingListActiveAddonsRequireAuth(t *testing.T) {
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"})
	h := NewBillingHandler(pr, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/addons", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestBillingListActiveAddonsPublicRPC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_active_addons" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"type": "llm", "units": 1},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := NewBillingHandler(pr, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	// Without auth — only tests route registration; full auth tested in integration.
	req := httptest.NewRequest(http.MethodGet, "/v1/billing/addons", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestBillingUnsubscribeInvalidAddonID(t *testing.T) {
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"})
	h := NewBillingHandler(pr, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodDelete, "/v1/billing/addons/not-a-number", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}
