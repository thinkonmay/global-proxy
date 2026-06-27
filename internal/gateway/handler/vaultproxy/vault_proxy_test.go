package vaultproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllowedVaultPath(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/vault/v1/auth/userpass/login/virtdaemon", true},
		{http.MethodPost, "/vault/v1/pki/issue/virtdaemon", true},
		{http.MethodGet, "/vault/v1/pki/ca/pem", true},
		{http.MethodGet, "/vault/v1/secret/data/foo", false},
		{http.MethodPost, "/vault/v1/pki/root/generate/internal", false},
		{http.MethodDelete, "/vault/v1/pki/issue/virtdaemon", false},
	}
	for _, tc := range tests {
		if got := allowedVaultPath(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s: got %v want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestServe_allowlistedPathWithoutServiceKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	h := New(upstream.URL, "service-key", http.DefaultTransport)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/vault/v1/auth/userpass/login/virtdaemon", strings.NewReader(`{"password":"x"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/vault/v1/auth/userpass/login/virtdaemon", strings.NewReader(`{"password":"x"}`))
	req.Header.Set("Authorization", "Bearer service-key")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServe_blocksDisallowedPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := New(upstream.URL, "service-key", http.DefaultTransport)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/vault/v1/secret/data/foo", nil)
	req.Header.Set("Authorization", "Bearer service-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
}

func TestServe_stripsGatewayAuthHeaders(t *testing.T) {
	var gotAuth, gotAPIKey, gotVaultToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("apikey")
		gotVaultToken = r.Header.Get("X-Vault-Token")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	h := New(upstream.URL, "service-key", http.DefaultTransport)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/vault/v1/auth/userpass/login/virtdaemon", strings.NewReader(`{"password":"x"}`))
	req.Header.Set("apikey", "service-key")
	req.Header.Set("Authorization", "Bearer service-key")
	req.Header.Set("X-Vault-Token", "vault-session-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotAuth != "" {
		t.Fatalf("Authorization forwarded=%q want empty", gotAuth)
	}
	if gotAPIKey != "" {
		t.Fatalf("apikey forwarded=%q want empty", gotAPIKey)
	}
	if gotVaultToken != "vault-session-token" {
		t.Fatalf("X-Vault-Token=%q want vault-session-token", gotVaultToken)
	}
}

func TestServe_stripsVaultPrefix(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	h := New(upstream.URL, "service-key", http.DefaultTransport)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/vault/v1/pki/ca/pem", nil)
	req.Header.Set("apikey", "service-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if gotPath != "/v1/pki/ca/pem" {
		t.Fatalf("upstream path=%q want /v1/pki/ca/pem", gotPath)
	}
}
