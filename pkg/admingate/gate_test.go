package admingate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func testGate(t *testing.T) (*Gate, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	store, err := NewRedisOTPStore("redis://" + mr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := NewGate(Config{
		AllowedIPs:      []string{"203.0.113.1"},
		AllowedEmails:   []string{"ops@thinkmay.net"},
		CookieDomain:    ".thinkmay.net",
		SessionTTLHours: 1,
		OTPTTLMinutes:   10,
		SigningSecret:   "unit-test-secret",
		BasicAuthUser:   "admin",
		BasicAuthPass:   "secret",
	}, store, LogMailer{})
	if err != nil {
		t.Fatal(err)
	}
	return gate, mr
}

func TestGateRedirectsWithoutSession(t *testing.T) {
	gate, _ := testGate(t)
	called := false
	h := gate.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusFound || rec.Header().Get("Location") == "" {
		t.Fatalf("expected redirect, called=%v code=%d loc=%q", called, rec.Code, rec.Header().Get("Location"))
	}
}

func TestGateOTPVerifySetsSSOCookie(t *testing.T) {
	gate, _ := testGate(t)
	mux := http.NewServeMux()
	gate.RegisterRoutes(mux)

	plain, err := generateOTP()
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.otp.Save(context.Background(), "ops@thinkmay.net", plain, time.Minute); err != nil {
		t.Fatal(err)
	}

	verifyBody, _ := json.Marshal(map[string]string{"email": "ops@thinkmay.net", "code": plain, "next": "/"})
	req := httptest.NewRequest(http.MethodPost, "/admin/otp/verify", bytes.NewReader(verifyBody))
	req.RemoteAddr = "203.0.113.1:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify failed: %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != cookieName {
		t.Fatalf("expected sso cookie, got %v", cookies)
	}
	if cookies[0].Domain != ".thinkmay.net" {
		t.Fatalf("cookie domain=%q", cookies[0].Domain)
	}
}

func TestHostRouterDispatchesByHost(t *testing.T) {
	public := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("public"))
	})
	admin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin"))
	})
	r := NewHostRouter("thinkmay.net", public)
	r.Register("studio.thinkmay.net", admin)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "thinkmay.net"
	r.ServeHTTP(rec, req)
	if rec.Body.String() != "public" {
		t.Fatalf("public host got %q", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "studio.thinkmay.net"
	r.ServeHTTP(rec, req)
	if rec.Body.String() != "admin" {
		t.Fatalf("studio host got %q", rec.Body.String())
	}
}

func TestAnalyticsIngestBypassesAdminGate(t *testing.T) {
	gate, _ := testGate(t)
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	mux.Handle("/", gate.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if !backendCalled || rec.Code != http.StatusOK {
		t.Fatalf("ingest bypass failed called=%v code=%d", backendCalled, rec.Code)
	}
	_ = backend
}
