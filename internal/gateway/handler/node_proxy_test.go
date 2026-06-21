package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestNodeProxyMissingCluster(t *testing.T) {
	h := NewNodeProxyHandler(nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/volumes/snapshots?cluster=", nil)
	req.Header.Set("Authorization", "Bearer test")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestNodeProxyForwardSnapshots(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(gatewayInternalHeader) != "1" {
			t.Fatalf("missing internal header")
		}
		if r.URL.Path != "/internal/snapshots" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer upstream.Close()

	host := upstream.URL
	ConfigurePocketBaseAuth(config.PocketBase{}, testIssuerRegistry(host, host))
	h := NewNodeProxyHandler(nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/volumes/snapshots?cluster="+url.QueryEscape(host), nil)
	req.Header.Set("Authorization", "Bearer user")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}
