package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/thinkonmay/global-proxy/api/config"
)

func testUserJWT(t *testing.T, userID string) string {
	t.Helper()
	tok, err := security.NewJWT(map[string]any{
		core.TokenClaimId:           userID,
		core.TokenClaimCollectionId: "_pb_users_auth_",
		core.TokenClaimType:         "auth",
		core.TokenClaimRefreshable:  true,
	}, "test-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRequireUserUsesCachedValidator(t *testing.T) {
	const userID = "u1"
	token := testUserJWT(t, userID)
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/collections/users/records/"+userID {
			t.Fatalf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"u1","email":"user@example.com"}`))
	}))
	t.Cleanup(pb.Close)

	ConfigurePocketBaseAuth(config.PocketBase{
		URL:        pb.URL,
		IssuerHost: "https://haiphong.thinkmay.net",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/test?issuer=https://haiphong.thinkmay.net", nil)
	req.Header.Set("Authorization", token)

	email, ok, status, msg := requireUser(context.Background(), req, nil)
	if !ok {
		t.Fatalf("requireUser failed: status=%d msg=%q", status, msg)
	}
	if email != "user@example.com" {
		t.Fatalf("email = %q", email)
	}
}

func TestRequireUserMissingAuth(t *testing.T) {
	ConfigurePocketBaseAuth(config.PocketBase{URL: "https://haiphong.thinkmay.net"})

	req := httptest.NewRequest(http.MethodGet, "/v1/test?issuer=https://haiphong.thinkmay.net", nil)
	_, ok, status, msg := requireUser(context.Background(), req, nil)
	if ok || status != http.StatusUnauthorized || msg != "authorization required" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestRequireUserMissingIssuer(t *testing.T) {
	ConfigurePocketBaseAuth(config.PocketBase{URL: "https://haiphong.thinkmay.net"})

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer tok")
	_, ok, status, msg := requireUser(context.Background(), req, nil)
	if ok || status != http.StatusBadRequest || msg != "issuer query required" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestRequireUserAuthFailure(t *testing.T) {
	token := testUserJWT(t, "u1")
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(pb.Close)

	ConfigurePocketBaseAuth(config.PocketBase{URL: pb.URL})

	req := httptest.NewRequest(http.MethodGet, "/v1/test?issuer="+pb.URL, nil)
	req.Header.Set("Authorization", token)
	_, ok, status, msg := requireUser(context.Background(), req, nil)
	if ok || status != http.StatusUnauthorized || msg != "pocketbase auth failed" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestPWAAuthFromRequestUsesValidator(t *testing.T) {
	token := testUserJWT(t, "u1")
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"u1","email":"thinkmay@dev.net"}`))
	}))
	t.Cleanup(pb.Close)

	ConfigurePocketBaseAuth(config.PocketBase{URL: pb.URL})

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/persona/recommendations", nil)
	req.Header.Set("Authorization", token)

	auth, status, msg := pwaAuthFromRequest(context.Background(), nil, req, pb.URL)
	if status != 0 || msg != "" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
	if auth.Email != "thinkmay@dev.net" || auth.UserID != "u1" {
		t.Fatalf("auth = %+v", auth)
	}
}

func TestPWAAuthFromRequestMissingIssuer(t *testing.T) {
	ConfigurePocketBaseAuth(config.PocketBase{URL: "https://haiphong.thinkmay.net"})

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/persona/recommendations", nil)
	req.Header.Set("Authorization", "tok")
	_, status, msg := pwaAuthFromRequest(context.Background(), nil, req, "")
	if status != http.StatusBadRequest || msg != "Missing issuer" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
}

func TestPWAAuthFromRequestMissingAuthHeader(t *testing.T) {
	ConfigurePocketBaseAuth(config.PocketBase{URL: "https://haiphong.thinkmay.net"})

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/persona/recommendations", nil)
	_, status, msg := pwaAuthFromRequest(context.Background(), nil, req, "https://haiphong.thinkmay.net")
	if status != http.StatusUnauthorized || msg != "Unauthorized: No auth header" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
}
