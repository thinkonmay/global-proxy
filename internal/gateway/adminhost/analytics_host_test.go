package adminhost

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/cors"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
)

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
	handler := cors.Middleware(cfg)(router)

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
