package guard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPathWAFAllowsCatalogPOSTWithoutIPCheck(t *testing.T) {
	called := false
	h := PathWAF(PathWAFConfig{
		AllowedIPs:      []string{"203.0.113.1"},
		PublicReadPaths: []string{"/rest/v1/stores"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/rest/v1/stores", nil)
	req.RemoteAddr = "198.51.100.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("POST should bypass WAF IP check, called=%v code=%d", called, rec.Code)
	}
}

func TestPathWAFAllowsNonCatalogPath(t *testing.T) {
	called := false
	h := PathWAF(PathWAFConfig{
		AllowedIPs:      []string{"203.0.113.1"},
		PublicReadPaths: []string{"/rest/v1/stores"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/users", nil)
	req.RemoteAddr = "198.51.100.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected pass-through, got called=%v code=%d", called, rec.Code)
	}
}

func TestPathWAFBlocksCatalogFromUnknownIP(t *testing.T) {
	h := PathWAF(PathWAFConfig{
		AllowedIPs:      []string{"203.0.113.1"},
		PublicReadPaths: []string{"/rest/v1/stores"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/stores", nil)
	req.RemoteAddr = "198.51.100.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestPathWAFAllowsCatalogFromListedIP(t *testing.T) {
	called := false
	h := PathWAF(PathWAFConfig{
		AllowedIPs:      []string{"203.0.113.1"},
		PublicReadPaths: []string{"/rest/v1/stores"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/stores?id=eq.1", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected allow, got called=%v code=%d", called, rec.Code)
	}
}
