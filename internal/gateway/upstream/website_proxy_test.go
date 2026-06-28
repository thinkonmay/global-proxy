package upstream

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsGatewayAPIPath(t *testing.T) {
	t.Parallel()
	api := []string{
		"/rest/v1/users",
		"/graphql/v1",
		"/storage/v1/object/public/x",
		"/pg/tables",
		"/api/pwa/plans",
		"/api/plans",
		"/v1/billing/wallet",
		"/v1/files/list/foo",
		"/v1/volumes/snapshots",
		"/v1/sse",
		"/health",
		"/jobs",
	}
	for _, path := range api {
		if !isGatewayAPIPath(path) {
			t.Errorf("expected API path %q", path)
		}
	}
	ui := []string{
		"/",
		"/en/",
		"/vi/dashboard/",
		"/_next/static/chunks/main.js",
		"/favicon.ico",
	}
	for _, path := range ui {
		if isGatewayAPIPath(path) {
			t.Errorf("expected website path %q", path)
		}
	}
}

func TestWrapWebsiteFallbackRoutesAPI(t *testing.T) {
	t.Parallel()
	apiHit := false
	webHit := false
	primary := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHit = true
		w.WriteHeader(http.StatusOK)
	})
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webHit = true
	})
	h := WrapWebsiteFallback(primary, website)

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/plans", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !apiHit || webHit {
		t.Fatalf("api=%v web=%v", apiHit, webHit)
	}
}

func TestWrapWebsiteFallbackRoutesPages(t *testing.T) {
	t.Parallel()
	apiHit := false
	webHit := false
	var webPath string
	primary := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHit = true
	})
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webHit = true
		webPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	h := WrapWebsiteFallback(primary, website)

	req := httptest.NewRequest(http.MethodGet, "/en/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if apiHit || !webHit {
		t.Fatalf("api=%v web=%v", apiHit, webHit)
	}
	if webPath != "/en/" {
		t.Fatalf("website path = %q, want /en/", webPath)
	}
}

func TestWrapWebsiteFallbackRoutesLocalePrefixedAPI(t *testing.T) {
	t.Parallel()
	var apiPath string
	primary := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("website should not handle locale-prefixed API paths")
	})
	h := WrapWebsiteFallback(primary, website)

	req := httptest.NewRequest(http.MethodGet, "/en/v1/billing/wallet", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if apiPath != "/v1/billing/wallet" {
		t.Fatalf("api path = %q, want /v1/billing/wallet", apiPath)
	}
}
