package pocketbase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
)

func testUserJWT(t *testing.T, userID string) string {
	t.Helper()
	tok, err := security.NewJWT(map[string]any{
		core.TokenClaimId:           userID,
		core.TokenClaimCollectionId: "_pb_users_auth_",
		core.TokenClaimType:         tokenTypeAuth,
		core.TokenClaimRefreshable:  true,
	}, "test-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestUserTokenValidatorHomeIssuerFetch(t *testing.T) {
	const userID = "u1"
	token := testUserJWT(t, userID)
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != usersPath+userID {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"u1","email":"user@example.com"}`))
	}))
	t.Cleanup(pb.Close)

	v := NewUserTokenValidator(UserTokenValidatorConfig{
		URL:        pb.URL,
		IssuerHost: "https://haiphong.thinkmay.net",
	})

	auth, err := v.Validate(context.Background(), "https://haiphong.thinkmay.net", token, nil)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if auth.Email != "user@example.com" || auth.UserID != "u1" {
		t.Fatalf("auth = %+v", auth)
	}

	auth2, err := v.Validate(context.Background(), "https://haiphong.thinkmay.net", token, nil)
	if err != nil {
		t.Fatalf("cached Validate: %v", err)
	}
	if auth2 != auth {
		t.Fatalf("cache miss: %+v vs %+v", auth2, auth)
	}
}

func TestUserTokenValidatorRemoteIssuerPassthrough(t *testing.T) {
	const userID = "u1"
	token := testUserJWT(t, userID)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"u1","email":"remote@example.com"}`))
	}))
	t.Cleanup(remote.Close)

	v := NewUserTokenValidator(UserTokenValidatorConfig{
		URL:        "https://host.docker.internal",
		IssuerHost: "https://haiphong.thinkmay.net",
	})

	auth, err := v.Validate(context.Background(), remote.URL, token, nil)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if auth.Email != "remote@example.com" {
		t.Fatalf("email = %q", auth.Email)
	}
}

func TestUserTokenValidatorAuthRefreshFallback(t *testing.T) {
	const userID = "u1"
	token := testUserJWT(t, userID)
	var gotRefresh bool
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, usersPath):
			w.WriteHeader(http.StatusForbidden)
			return
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth-refresh"):
			gotRefresh = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"new","record":{"id":"u1","email":"fallback@example.com"}}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(pb.Close)

	v := NewUserTokenValidator(UserTokenValidatorConfig{URL: pb.URL})
	auth, err := v.Validate(context.Background(), pb.URL, token, nil)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !gotRefresh {
		t.Fatal("expected auth-refresh fallback")
	}
	if auth.Email != "fallback@example.com" {
		t.Fatalf("email = %q", auth.Email)
	}
}

func TestUserTokenValidatorInvalidToken(t *testing.T) {
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(pb.Close)

	v := NewUserTokenValidator(UserTokenValidatorConfig{URL: pb.URL})
	_, err := v.Validate(context.Background(), pb.URL, "bad", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHostFromBaseURL(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://haiphong.thinkmay.net:443", "haiphong.thinkmay.net"},
		{"haiphong.thinkmay.net", "haiphong.thinkmay.net"},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			if got := hostFromBaseURL(tc.raw); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestIntegrationUserTokenValidator(t *testing.T) {
	env := startPocketBase(t)
	email := "validator@example.com"
	pass := "userpass123"
	client := testClient(env.URL)
	ctx := context.Background()
	if err := client.CreateRecord(ctx, "users", map[string]any{
		"email": email, "password": pass, "passwordConfirm": pass, "name": email,
	}, nil); err != nil {
		t.Fatal(err)
	}
	tok := userAuthToken(t, env.URL, email, pass)

	v := NewUserTokenValidator(UserTokenValidatorConfig{URL: env.URL})
	auth, err := v.Validate(ctx, env.URL, tok, nil)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if auth.Email != email {
		t.Fatalf("email = %q", auth.Email)
	}

	auth2, err := v.Validate(ctx, env.URL, tok, nil)
	if err != nil {
		t.Fatalf("cached Validate: %v", err)
	}
	if auth2.Email != email {
		t.Fatalf("cached email = %q", auth2.Email)
	}
}
