package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/testsupport"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func testGoTrueJWT(t *testing.T, secret, userID, email string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"role":  "authenticated",
		"aud":   "authenticated",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRequireUserAcceptsGoTrueToken(t *testing.T) {
	const secret = "gotrue-test-secret"
	ConfigureGoTrueAuth(secret)

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+testGoTrueJWT(t, secret, "550e8400-e29b-41d4-a716-446655440000", "gotrue@example.com"))

	email, ok, status, msg := RequireUser(context.Background(), req, nil)
	if !ok {
		t.Fatalf("requireUser failed: status=%d msg=%q", status, msg)
	}
	if email != "gotrue@example.com" {
		t.Fatalf("email = %q", email)
	}
}

func TestRequireUserMissingAuth(t *testing.T) {
	ConfigureGoTrueAuth("secret")

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	_, ok, status, msg := RequireUser(context.Background(), req, nil)
	if ok || status != http.StatusUnauthorized || msg != "authorization required" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestRequireUserRejectsInvalidToken(t *testing.T) {
	ConfigureGoTrueAuth("right-secret")

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+testGoTrueJWT(t, "wrong-secret", "u1", "user@example.com"))
	_, ok, status, msg := RequireUser(context.Background(), req, nil)
	if ok || status != http.StatusUnauthorized || msg != "auth failed" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestRequireUserAuthNotConfigured(t *testing.T) {
	gotrueUserAuth = nil

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer tok")
	_, ok, status, msg := RequireUser(context.Background(), req, nil)
	if ok || status != http.StatusServiceUnavailable || msg != "auth not configured" {
		t.Fatalf("ok=%v status=%d msg=%q", ok, status, msg)
	}
}

func TestPWAAuthFromRequestUsesGoTrue(t *testing.T) {
	const secret = "gotrue-test-secret"
	ConfigureGoTrueAuth(secret)

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/persona/recommendations", nil)
	req.Header.Set("Authorization", "Bearer "+testGoTrueJWT(t, secret, "u1", "thinkmay@dev.net"))

	usr, status, msg := PWAAuthFromRequest(context.Background(), nil, req)
	if status != 0 || msg != "" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
	if usr.Email != "thinkmay@dev.net" || usr.UserID != "u1" {
		t.Fatalf("usr = %+v", usr)
	}
}

func TestPWAAuthFromRequestMissingAuthHeader(t *testing.T) {
	ConfigureGoTrueAuth("secret")

	req := httptest.NewRequest(http.MethodGet, "/api/pwa/persona/recommendations", nil)
	_, status, msg := PWAAuthFromRequest(context.Background(), nil, req)
	if status != http.StatusUnauthorized || msg != "Unauthorized: No auth header" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
}

func TestValidateAcceptsGoTrueToken(t *testing.T) {
	const secret = "gotrue-test-secret"
	ConfigureGoTrueAuth(secret)
	tok := testsupport.GoTrueJWT(t, secret, "uid-1", "user@example.com")

	email, userID, status, msg := Validate(context.Background(), "Bearer "+tok, nil)
	if status != 0 || msg != "" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
	if email != "user@example.com" || userID != "uid-1" {
		t.Fatalf("email=%q userID=%q", email, userID)
	}
}

func TestValidateRejectsExpiredToken(t *testing.T) {
	const secret = "gotrue-test-secret"
	ConfigureGoTrueAuth(secret)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "uid-1",
		"email": "user@example.com",
		"role":  "authenticated",
		"aud":   "authenticated",
		"exp":   time.Now().Add(-time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	_, _, status, msg := Validate(context.Background(), "Bearer "+s, nil)
	if status != http.StatusUnauthorized || msg != "auth failed" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
}

func TestConfigureAuthLinksUserOnRequireUser(t *testing.T) {
	const secret = "gotrue-test-secret"
	var linked map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/link_auth_user_v1" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&linked)
		_ = json.NewEncoder(w).Encode(int64(42))
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	ConfigureAuth(pr, config.PocketBase{}, config.Supabase{JWTSecret: secret})

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+testsupport.GoTrueJWT(t, secret, "auth-sub", "linked@example.com"))
	_, ok, _, _ := RequireUser(context.Background(), req, nil)
	if !ok {
		t.Fatal("expected auth ok")
	}
	if linked["auth_user_id"] != "auth-sub" || linked["email"] != "linked@example.com" {
		t.Fatalf("link_auth_user_v1 args = %v", linked)
	}
}

func TestResolveClusterURLUnknownIssuer(t *testing.T) {
	ConfigureClusterRegistry(testsupport.TestIssuerRegistry("http://home", "home.thinkmay.net"))

	_, status, msg := ResolveClusterURL(context.Background(), "unknown.cluster")
	if status != http.StatusForbidden || msg != "invalid cluster" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
}
