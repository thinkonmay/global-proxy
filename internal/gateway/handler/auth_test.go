package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestRequireUserRewritesIssuerToInternal(t *testing.T) {
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/collections/users/auth-refresh" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"t","record":{"email":"user@example.com"}}`))
	}))
	t.Cleanup(pb.Close)

	ConfigurePocketBaseAuth(config.PocketBase{
		URL:         "https://haiphong.thinkmay.net",
		InternalURL: pb.URL,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/test?issuer=https://haiphong.thinkmay.net", nil)
	req.Header.Set("Authorization", "test-jwt")

	email, ok, status, msg := requireUser(context.Background(), req, nil)
	if !ok {
		t.Fatalf("requireUser failed: status=%d msg=%q", status, msg)
	}
	if email != "user@example.com" {
		t.Fatalf("email = %q", email)
	}
}

func TestRequireUserMissingAuth(t *testing.T) {
	ConfigurePocketBaseAuth(config.PocketBase{
		URL:         "https://haiphong.thinkmay.net",
		InternalURL: "https://host.docker.internal",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/test?issuer=https://haiphong.thinkmay.net", nil)
	_, ok, status, msg := requireUser(context.Background(), req, nil)
	if ok || status != http.StatusUnauthorized || msg != "authorization required" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestRequireUserMissingIssuer(t *testing.T) {
	ConfigurePocketBaseAuth(config.PocketBase{
		URL:         "https://haiphong.thinkmay.net",
		InternalURL: "https://host.docker.internal",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer tok")
	_, ok, status, msg := requireUser(context.Background(), req, nil)
	if ok || status != http.StatusBadRequest || msg != "issuer query required" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestRequireUserAuthRefreshFailure(t *testing.T) {
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"invalid"}`))
	}))
	t.Cleanup(pb.Close)

	ConfigurePocketBaseAuth(config.PocketBase{
		URL:         "https://haiphong.thinkmay.net",
		InternalURL: pb.URL,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/test?issuer=https://haiphong.thinkmay.net", nil)
	req.Header.Set("Authorization", "bad")
	_, ok, status, msg := requireUser(context.Background(), req, nil)
	if ok || status != http.StatusUnauthorized || msg != "pocketbase auth refresh failed" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestPWAAuthFromRequestUsesInternalIssuer(t *testing.T) {
	var gotHost string
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"t","record":{"id":"u1","email":"thinkmay@dev.net"}}`))
	}))
	t.Cleanup(pb.Close)

	ConfigurePocketBaseAuth(config.PocketBase{
		URL:         "https://haiphong.thinkmay.net",
		InternalURL: pb.URL,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/persona/recommendations", nil)
	req.Header.Set("Authorization", "raw-token")

	auth, status, msg := pwaAuthFromRequest(context.Background(), nil, req, "https://haiphong.thinkmay.net")
	if status != 0 || msg != "" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
	if auth.Email != "thinkmay@dev.net" || auth.UserID != "u1" {
		t.Fatalf("auth = %+v", auth)
	}
	if gotHost == "" {
		t.Fatal("expected auth-refresh request to internal PB server")
	}
}

func TestPWAAuthFromRequestMissingIssuer(t *testing.T) {
	ConfigurePocketBaseAuth(config.PocketBase{
		URL:         "https://haiphong.thinkmay.net",
		InternalURL: "https://host.docker.internal",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/persona/recommendations", nil)
	req.Header.Set("Authorization", "tok")
	_, status, msg := pwaAuthFromRequest(context.Background(), nil, req, "")
	if status != http.StatusBadRequest || msg != "Missing issuer" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
}

func TestPWAAuthFromRequestMissingAuthHeader(t *testing.T) {
	ConfigurePocketBaseAuth(config.PocketBase{
		URL:         "https://haiphong.thinkmay.net",
		InternalURL: "https://host.docker.internal",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/persona/recommendations", nil)
	_, status, msg := pwaAuthFromRequest(context.Background(), nil, req, "https://haiphong.thinkmay.net")
	if status != http.StatusUnauthorized || msg != "Unauthorized: No auth header" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
}
