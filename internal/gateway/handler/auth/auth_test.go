package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
