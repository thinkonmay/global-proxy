package pocketbase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRefreshAuthUsesInternalResolver(t *testing.T) {
	var gotHost string
	internal := newAuthRefreshServer(t, func(r *http.Request) {
		gotHost = r.Host
		if r.Header.Get("Authorization") != "Bearer raw-jwt-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
	})

	resolver := NewIssuerResolver("https://haiphong.thinkmay.net", internal)
	email, err := UserEmailFromRefresh(
		context.Background(),
		resolver,
		"https://haiphong.thinkmay.net",
		"raw-jwt-token",
		nil,
	)
	if err != nil {
		t.Fatalf("UserEmailFromRefresh: %v", err)
	}
	if email != "thinkmay@dev.net" {
		t.Fatalf("email = %q", email)
	}
	if gotHost != hostOnly(internal) {
		t.Fatalf("Host = %q, want internal server %q", gotHost, hostOnly(internal))
	}
}

func TestRefreshAuthPassthroughDifferentIssuer(t *testing.T) {
	var gotHost string
	remote := newAuthRefreshServer(t, func(r *http.Request) {
		gotHost = r.Host
	})

	resolver := NewIssuerResolver("https://haiphong.thinkmay.net", "https://host.docker.internal")
	_, err := RefreshAuth(
		context.Background(),
		resolver,
		remote,
		"users",
		"Bearer tok",
		nil,
	)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if gotHost != hostOnly(remote) {
		t.Fatalf("Host = %q, want remote server %q", gotHost, hostOnly(remote))
	}
}

func TestRefreshAuthBearerPrefixOptional(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantAuth string
	}{
		{"already prefixed", "Bearer already-prefixed", "Bearer already-prefixed"},
		{"raw token", "raw-jwt-token", "Bearer raw-jwt-token"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotAuth string
			internal := newAuthRefreshServer(t, func(r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
			})

			resolver := NewIssuerResolver("https://haiphong.thinkmay.net", internal)
			_, err := RefreshAuth(
				context.Background(),
				resolver,
				"https://haiphong.thinkmay.net",
				"users",
				tc.token,
				nil,
			)
			if err != nil {
				t.Fatalf("RefreshAuth: %v", err)
			}
			if gotAuth != tc.wantAuth {
				t.Fatalf("Authorization = %q, want %q", gotAuth, tc.wantAuth)
			}
		})
	}
}

func TestRefreshAuthInvalidToken(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"invalid token"}`))
	}))
	defer internal.Close()

	resolver := NewIssuerResolver("https://haiphong.thinkmay.net", internal.URL)
	_, err := RefreshAuth(
		context.Background(),
		resolver,
		"https://haiphong.thinkmay.net",
		"users",
		"bad",
		nil,
	)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func newAuthRefreshServer(t *testing.T, check func(*http.Request)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/collections/users/auth-refresh" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if check != nil {
			check(r)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"refreshed","record":{"id":"u1","email":"thinkmay@dev.net"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func hostOnly(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}
