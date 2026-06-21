package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
)

func TestRybbitIngestProxiedOnPublicHost(t *testing.T) {
	var gotPath, gotMethod string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	cfg := &config.Config{
		Admin: config.Admin{
			Upstreams: config.AdminUpstreams{RybbitBackend: backend.URL},
		},
	}
	registerRybbitIngestRoutes(mux, cfg, http.DefaultTransport)

	for _, tc := range []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodPost, "/api/track", "/api/track"},
		{http.MethodPost, "/api/identify", "/api/identify"},
		{http.MethodGet, "/api/script.js", "/api/script.js"},
		{http.MethodGet, "/api/site/tracking-config/1", "/api/site/tracking-config/1"},
		{http.MethodPost, "/api/session-replay/record/1", "/api/session-replay/record/1"},
	} {
		gotPath, gotMethod = "", ""
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: status=%d body=%q", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if gotPath != tc.want || gotMethod != tc.method {
			t.Fatalf("%s %s: upstream got %s %s, want %s %s", tc.method, tc.path, gotMethod, gotPath, tc.method, tc.want)
		}
	}
}

func TestAnalyticsHostAllowsPublicOriginCORS(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &config.Config{
		TLS: config.TLS{
			HTTPSPort: "4433",
			Hosts:     []string{"haiphong.thinkmay.net", "analytics.haiphong.thinkmay.net"},
		},
		Gateway: config.Gateway{PublicURL: "https://haiphong.thinkmay.net:4433"},
		Admin: config.Admin{
			Hosts: config.AdminHosts{
				Public:    "haiphong.thinkmay.net",
				Analytics: "analytics.haiphong.thinkmay.net",
			},
			Ingest: config.AdminIngest{AnalyticsPrefix: "/api/"},
			Upstreams: config.AdminUpstreams{
				RybbitBackend: backend.URL,
			},
		},
	}

	public := http.NewServeMux()
	router := admingate.NewHostRouter(cfg.Admin.Hosts.Public, public)
	registerAnalyticsHost(router, cfg, nil, http.DefaultTransport)
	handler := corsMiddleware(cfg)(router)

	req := httptest.NewRequest(http.MethodOptions, "/api/track", nil)
	req.Host = "analytics.haiphong.thinkmay.net"
	req.Header.Set("Origin", "https://haiphong.thinkmay.net:4433")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status=%d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://haiphong.thinkmay.net:4433" {
		t.Fatalf("Allow-Origin=%q", got)
	}
}
