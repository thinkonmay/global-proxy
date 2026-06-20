package pocketbase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(baseURL, user, pass string) *Client {
	return New(Config{URL: baseURL, Username: user, Password: pass})
}

func TestConfigured(t *testing.T) {
	if newTestClient("http://pb", "admin@test.com", "secret").Configured() != true {
		t.Fatal("expected configured client")
	}
	if newTestClient("", "admin@test.com", "secret").Configured() != false {
		t.Fatal("expected missing url")
	}
}

func TestAuthOnceReusesToken(t *testing.T) {
	var authCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == authWithPassword:
			authCalls.Add(1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["identity"] != "admin@test.com" || body["password"] != "secret" {
				t.Errorf("auth body = %+v", body)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"tok-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/users/records":
			if r.Header.Get("Authorization") != "Bearer tok-1" {
				t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "admin@test.com", "secret")
	ctx := context.Background()

	var out1, out2 map[string]any
	if err := c.ListRecords(ctx, "users", nil, &out1); err != nil {
		t.Fatalf("first ListRecords: %v", err)
	}
	if err := c.ListRecords(ctx, "users", nil, &out2); err != nil {
		t.Fatalf("second ListRecords: %v", err)
	}
	if authCalls.Load() != 1 {
		t.Fatalf("auth calls = %d, want 1", authCalls.Load())
	}
}

func TestUnauthorizedRetriesLoginOnce(t *testing.T) {
	var authCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == authRefreshPath:
			w.WriteHeader(http.StatusUnauthorized)
			return
		case r.Method == http.MethodPost && r.URL.Path == authWithPassword:
			n := authCalls.Add(1)
			token := "tok-1"
			if n == 2 {
				token = "tok-2"
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"` + token + `"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/volumes/records":
			auth := r.Header.Get("Authorization")
			if auth == "Bearer tok-1" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
				return
			}
			if auth != "Bearer tok-2" {
				t.Fatalf("Authorization = %q", auth)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[{"id":"1"}]}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "admin@test.com", "secret")
	var out map[string]any
	if err := c.ListRecords(context.Background(), "volumes", url.Values{"filter": {"status='ready'"}}, &out); err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if authCalls.Load() != 2 {
		t.Fatalf("auth calls = %d, want 2", authCalls.Load())
	}
}

func TestCreateRecordPostsJSON(t *testing.T) {
	var gotMethod, gotAuth, gotContentType string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == authWithPassword {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"tok-1"}`))
			return
		}
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"rec-1","name":"demo"}`))
	}))
	defer srv.Close()

	var out map[string]any
	err := newTestClient(srv.URL, "admin@test.com", "secret").CreateRecord(
		context.Background(),
		"volumes",
		map[string]any{"name": "demo"},
		&out,
	)
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotAuth != "Bearer tok-1" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	if gotBody["name"] != "demo" {
		t.Errorf("body = %+v", gotBody)
	}
	if out["id"] != "rec-1" {
		t.Errorf("out = %+v", out)
	}
}

func TestWithBaseURLUsesSeparateTokenCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == authWithPassword {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"tok-1"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	base := newTestClient(srv.URL, "admin@test.com", "secret")
	other := base.WithBaseURL("https://other-cluster.example")
	if other == base {
		t.Fatal("expected distinct client for other base URL")
	}
	if other.baseURL != "https://other-cluster.example" {
		t.Fatalf("baseURL = %q", other.baseURL)
	}
}

func TestNotConfiguredReturnsError(t *testing.T) {
	err := New(Config{}).Get(context.Background(), "/api/health", nil, nil)
	if err == nil || err.Error() != "pocketbase: url, username, and password required" {
		t.Fatalf("err = %v", err)
	}
}

func TestUnauthorizedRetriesAuthRefreshBeforeLogin(t *testing.T) {
	var authCalls, refreshCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == authWithPassword:
			authCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"tok-2"}`))
		case r.Method == http.MethodPost && r.URL.Path == authRefreshPath:
			refreshCalls.Add(1)
			if r.Header.Get("Authorization") != "tok-1" {
				t.Fatalf("refresh Authorization = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"tok-refreshed"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/volumes/records":
			auth := r.Header.Get("Authorization")
			if auth == "Bearer tok-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if auth != "Bearer tok-refreshed" {
				t.Fatalf("Authorization = %q", auth)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "admin@test.com", "secret")
	c.mu.Lock()
	c.authToken = "tok-1"
	c.tokenIssuedAt = time.Now()
	c.mu.Unlock()

	var out map[string]any
	if err := c.ListRecords(context.Background(), "volumes", nil, &out); err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if refreshCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshCalls.Load())
	}
	if authCalls.Load() != 0 {
		t.Fatalf("password auth calls = %d, want 0", authCalls.Load())
	}
}

func TestUserEmailFromRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/collections/users/auth-refresh" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer user-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"new-token","record":{"email":"user@example.com"}}`))
	}))
	defer srv.Close()

	email, err := UserEmailFromRefresh(context.Background(), srv.URL, "Bearer user-token", nil)
	if err != nil {
		t.Fatalf("UserEmailFromRefresh: %v", err)
	}
	if email != "user@example.com" {
		t.Fatalf("email = %q", email)
	}
}

func TestProactiveTokenRefreshAfterInterval(t *testing.T) {
	var refreshCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == authRefreshPath:
			refreshCalls.Add(1)
			if r.Header.Get("Authorization") != "tok-stale" {
				t.Fatalf("refresh Authorization = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"tok-fresh"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/users/records":
			if r.Header.Get("Authorization") != "Bearer tok-fresh" {
				t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "admin@test.com", "secret")
	c.mu.Lock()
	c.authToken = "tok-stale"
	c.tokenIssuedAt = time.Now().Add(-tokenRefreshInterval - time.Minute)
	c.mu.Unlock()

	var out map[string]any
	if err := c.ListRecords(context.Background(), "users", nil, &out); err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if refreshCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshCalls.Load())
	}
}

func TestIsNotFound(t *testing.T) {
	if !IsNotFound(&Error{Status: http.StatusNotFound}) {
		t.Fatal("expected not found")
	}
	if IsNotFound(&Error{Status: http.StatusBadRequest}) {
		t.Fatal("expected false for 400")
	}
}
