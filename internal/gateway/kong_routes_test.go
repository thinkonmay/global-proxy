package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
)

const (
	kongTestAnon    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.anon"
	kongTestService = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.service"
)

func kongTestCfg(restURL, storageURL, metaURL, studioURL string) *config.Config {
	return &config.Config{
		PostgREST: config.PostgREST{URL: restURL},
		Supabase: config.Supabase{
			AnonKey:           kongTestAnon,
			ServiceKey:        kongTestService,
			DashboardUser:     "admin",
			DashboardPassword: "pass",
		},
		Upstreams: config.Upstreams{
			Storage: storageURL,
			Meta:    metaURL,
			Studio:  studioURL,
		},
		WAF: config.WAF{
			AllowedIPs:      []string{"203.0.113.10"},
			PublicReadPaths: []string{"/rest/v1/stores"},
		},
	}
}

func TestKongRestRejectsInvalidAPIKey(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/plans", nil)
	req.Header.Set("apikey", "invalid-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestKongRestProxiesWithServiceRoleKey(t *testing.T) {
	var auth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/plans", nil)
	req.Header.Set("apikey", kongTestService)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || auth != "Bearer "+kongTestService {
		t.Fatalf("service_role proxy failed code=%d auth=%q", rec.Code, auth)
	}
}

func TestKongGraphQLSetsContentProfile(t *testing.T) {
	var profile string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile = r.Header.Get("Content-Profile")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodPost, "/graphql/v1", strings.NewReader(`{"query":"{}"}`))
	req.Header.Set("apikey", kongTestAnon)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || profile != "graphql_public" {
		t.Fatalf("graphql profile mismatch code=%d profile=%q", rec.Code, profile)
	}
}

func TestKongRestRequiresAPIKey(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), http.DefaultTransport)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rest/v1/users", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestKongRestProxiesWithAnonKey(t *testing.T) {
	var upstreamPath, auth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/stores?id=eq.1", nil)
	req.Header.Set("apikey", kongTestAnon)
	req.RemoteAddr = "203.0.113.10:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || upstreamPath != "/stores" || auth != "Bearer "+kongTestAnon {
		t.Fatalf("proxy mismatch code=%d path=%q auth=%q", rec.Code, upstreamPath, auth)
	}
}

func TestKongRestWAFAllowsCatalogPOSTFromUnknownIP(t *testing.T) {
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodPost, "/rest/v1/stores", nil)
	req.Header.Set("apikey", kongTestAnon)
	req.RemoteAddr = "198.51.100.5:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("POST should bypass WAF, called=%v code=%d", called, rec.Code)
	}
}

func TestKongRestWAFBlocksCatalogFromUnknownIP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/stores", nil)
	req.Header.Set("apikey", kongTestAnon)
	req.RemoteAddr = "198.51.100.5:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected WAF 403, got %d", rec.Code)
	}
}

func TestKongGraphQLRewritesPath(t *testing.T) {
	var upstreamPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodPost, "/graphql/v1", strings.NewReader(`{"query":"{}"}`))
	req.Header.Set("apikey", kongTestAnon)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || upstreamPath != "/rpc/graphql" {
		t.Fatalf("graphql rewrite failed code=%d path=%q", rec.Code, upstreamPath)
	}
}

func TestKongMetaRequiresServiceRole(t *testing.T) {
	called := false
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer meta.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg("", "", meta.URL, ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodGet, "/pg/tables", nil)
	req.Header.Set("apikey", kongTestAnon)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || called {
		t.Fatalf("expected admin-only block, code=%d called=%v", rec.Code, called)
	}
}

func TestKongStorageStripsEmptyAuthorization(t *testing.T) {
	var auth string
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer storage.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg("", storage.URL, "", ""), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodGet, "/storage/v1/object/public/bucket/x", nil)
	req.Header.Set("Authorization", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || auth != "" {
		t.Fatalf("expected cleared auth, code=%d auth=%q", rec.Code, auth)
	}
}

func TestKongRemovedRoutesReturn404(t *testing.T) {
	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg("", "", "", ""), http.DefaultTransport)

	for _, path := range []string{"/auth/v1/token", "/realtime/v1/websocket", "/functions/v1/hello"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s expected 404, got %d", path, rec.Code)
		}
	}
}

func TestKongMCPBlocked(t *testing.T) {
	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg("", "", "", ""), http.DefaultTransport)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/mcp", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestKongRestBreakerRejection(t *testing.T) {
	bt := guard.New(nil, guard.Config{MaxFailures: 1, Cooldown: time.Minute, MaxConcurrent: 1})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	registerKongRoutes(mux, kongTestCfg(backend.URL, "", "", ""), bt)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/other", nil)
	req.Header.Set("apikey", kongTestAnon)
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 global_unavailable, got %d body=%s", rec.Code, rec.Body.String())
	}
}
