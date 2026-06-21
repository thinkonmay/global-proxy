package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func testPWAConfig() config.Config {
	return config.Config{}
}

func TestPWAAppInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stores" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"name": "Test Game", "header_image": "https://cdn.example/header.jpg",
		}})
	}))
	t.Cleanup(srv.Close)

	h := NewPWAHandler(testPWAConfig(), postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil, NewPersonaHandler(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/app_info?id=123", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["name"] != "Test Game" {
		t.Fatalf("name=%q", out["name"])
	}
}

func TestPWACurrencyRates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"currency": "USD", "rate_to_system_credit": 1.0, "is_base": true,
		}})
	}))
	t.Cleanup(srv.Close)

	h := NewPWAHandler(testPWAConfig(), postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil, NewPersonaHandler(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/currency_rates", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestSanitizeCodeName(t *testing.T) {
	if got := sanitizeCodeName("  Hello World!! "); got != "hello_world" {
		t.Fatalf("got %q", got)
	}
}
