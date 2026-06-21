package main

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
		"/sse",
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
	h := wrapWebsiteFallback(primary, website)

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
	primary := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHit = true
	})
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webHit = true
		w.WriteHeader(http.StatusOK)
	})
	h := wrapWebsiteFallback(primary, website)

	req := httptest.NewRequest(http.MethodGet, "/en/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if apiHit || !webHit {
		t.Fatalf("api=%v web=%v", apiHit, webHit)
	}
}
