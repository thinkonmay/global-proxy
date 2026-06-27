package upstream

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func kongTestCfg(kongURL string) *config.Config {
	return &config.Config{
		Upstreams: config.Upstreams{Kong: kongURL},
	}
}

func TestPublicRestV1Denied(t *testing.T) {
	mux := http.NewServeMux()
	RegisterKong(mux, kongTestCfg(""), http.DefaultTransport)

	for _, path := range []string{
		"/rest/v1/plans",
		"/rest/v1/stores?id=eq.1",
		"/graphql/v1",
		"/storage/v1/status",
		"/pg/tables",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: expected 404, got %d body=%s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "internal-only") {
			t.Fatalf("%s: expected internal-only message, got %s", path, rec.Body.String())
		}
	}
}

func TestKongRemovedRoutesReturn404(t *testing.T) {
	mux := http.NewServeMux()
	RegisterKong(mux, kongTestCfg(""), http.DefaultTransport)

	for _, path := range []string{"/auth/v1/token", "/realtime/v1/websocket", "/functions/v1/hello"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s expected 404, got %d", path, rec.Code)
		}
	}
}

func TestKongGoTrueProxiesViaKong(t *testing.T) {
	var upstreamPath string
	kong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer kong.Close()

	mux := http.NewServeMux()
	RegisterKong(mux, kongTestCfg(kong.URL), http.DefaultTransport)

	req := httptest.NewRequest(http.MethodPost, "/auth/v1/token", strings.NewReader(`{"grant_type":"password"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if upstreamPath != "/auth/v1/token" {
		t.Fatalf("expected upstream /auth/v1/token (via Kong), got %q", upstreamPath)
	}
}

func TestKongGoTrueRejectsDirectAuthUpstream(t *testing.T) {
	mux := http.NewServeMux()
	cfg := kongTestCfg("")
	cfg.Upstreams.Kong = "http://auth:9999"
	RegisterKong(mux, cfg, http.DefaultTransport)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/v1/health", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when upstream is direct GoTrue, got %d", rec.Code)
	}
}

func TestKongMCPBlocked(t *testing.T) {
	mux := http.NewServeMux()
	RegisterKong(mux, kongTestCfg(""), http.DefaultTransport)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/mcp", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestKongPublicRPCRemoved(t *testing.T) {
	mux := http.NewServeMux()
	RegisterKong(mux, kongTestCfg(""), http.DefaultTransport)

	for _, path := range []string{"/v1/rpc", "/rest/v1/rpc/get_all_rank_rewards"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: expected 404, got %d", path, rec.Code)
		}
	}
}
