package cors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestCORSMiddlewareOptionsReflectsAllowedOrigin(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLS{HTTPSPort: "4433", Hosts: []string{"haiphong.thinkmay.net", "studio.haiphong.thinkmay.net"}},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("OPTIONS should not reach handler")
	})
	h := Middleware(cfg)(next)

	req := httptest.NewRequest(http.MethodOptions, "/storage/v1/upload/resumable", nil)
	req.Header.Set("Origin", "https://studio.haiphong.thinkmay.net:4433")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://studio.haiphong.thinkmay.net:4433" {
		t.Fatalf("Allow-Origin = %q", got)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("missing Allow-Credentials")
	}
}

func TestCORSMiddlewareSkipsWildcardForUnknownOrigin(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLS{HTTPSPort: "4433", Hosts: []string{"haiphong.thinkmay.net"}},
	}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v status=%d", called, rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected Allow-Origin %q for disallowed origin", got)
	}
}

func TestStripUpstreamCORS(t *testing.T) {
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "https://studio.example")
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Content-Type", "application/json")
	StripUpstream(h)
	if h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS not stripped")
	}
	if h.Get("Content-Type") != "application/json" {
		t.Fatal("non-CORS header removed")
	}
}

func TestBuildAllowedOriginsIncludesPort(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLS{
			HTTPSPort: "4433",
			HTTPPort:  "8080",
			Hosts:     []string{"studio.haiphong.thinkmay.net"},
		},
	}
	allowed := buildAllowedOrigins(cfg)
	if _, ok := allowed["https://studio.haiphong.thinkmay.net:4433"]; !ok {
		t.Fatal("missing https origin with port")
	}
	if _, ok := allowed["http://studio.haiphong.thinkmay.net:8080"]; !ok {
		t.Fatal("missing http origin with port")
	}
}

func TestCORSMiddlewareAllowsRybbitAPIKeyPreflight(t *testing.T) {
	cfg := &config.Config{
		TLS:     config.TLS{HTTPSPort: "4433", Hosts: []string{"haiphong.thinkmay.net", "analytics.haiphong.thinkmay.net"}},
		Gateway: config.Gateway{PublicURL: "https://haiphong.thinkmay.net:4433"},
	}
	h := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("OPTIONS should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/track", nil)
	req.Header.Set("Origin", "https://haiphong.thinkmay.net:4433")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-api-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://haiphong.thinkmay.net:4433" {
		t.Fatalf("Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(strings.ToLower(got), "x-api-key") {
		t.Fatalf("Allow-Headers = %q, want X-API-Key", got)
	}
}

func TestBuildAllowedOriginsUsesPublicURLPortOverTLSListenPort(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLS{
			HTTPSPort: "443",
			Hosts:     []string{"haiphong.thinkmay.net", "studio.haiphong.thinkmay.net"},
		},
		Gateway: config.Gateway{PublicURL: "https://haiphong.thinkmay.net:4433"},
	}
	allowed := buildAllowedOrigins(cfg)
	for _, origin := range []string{
		"https://haiphong.thinkmay.net:4433",
		"https://studio.haiphong.thinkmay.net:4433",
	} {
		if _, ok := allowed[origin]; !ok {
			t.Fatalf("missing allowed origin %q", origin)
		}
	}
}
