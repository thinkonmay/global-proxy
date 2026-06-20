package guard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var errDown = errors.New("down")

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestRateLimitPerKeyAndBurst(t *testing.T) {
	h := RateLimit(RateLimitConfig{RPS: 1, Burst: 2})(okHandler())
	call := func(ip string) int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// burst of 2 passes, 3rd from same IP is limited (each call spends a token)
	for i := range 2 {
		if got := call("1.1.1.1"); got != 200 {
			t.Fatalf("burst call %d = %d, want 200", i, got)
		}
	}
	if got := call("1.1.1.1"); got != http.StatusTooManyRequests {
		t.Errorf("3rd = %d, want 429", got)
	}
	// a different IP has its own bucket
	if got := call("2.2.2.2"); got != 200 {
		t.Errorf("other IP = %d, want 200 (per-key isolation)", got)
	}
}

func TestDenylistRejects(t *testing.T) {
	h := Denylist(IPSet("9.9.9.9"))(okHandler())
	call := func(ip string) int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = ip + ":1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := call("9.9.9.9"); got != http.StatusForbidden {
		t.Errorf("blacklisted = %d, want 403", got)
	}
	if got := call("1.2.3.4"); got != 200 {
		t.Errorf("other IP = %d, want 200", got)
	}
}

func TestAllowlistBypassesRateLimit(t *testing.T) {
	// Allowlist (outer) marks 7.7.7.7 bypassed; RateLimit (inner, Burst 1) must skip it.
	h := Chain(okHandler(),
		Allowlist(IPSet("7.7.7.7")),
		RateLimit(RateLimitConfig{RPS: 1, Burst: 1}),
	)
	call := func(ip string) int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = ip + ":1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := range 5 { // whitelisted: never limited despite Burst 1
		if got := call("7.7.7.7"); got != 200 {
			t.Fatalf("whitelisted call %d = %d, want 200", i, got)
		}
	}
	// a non-whitelisted IP still gets limited after the burst
	if call("8.8.8.8") != 200 {
		t.Fatal("first non-WL call should pass")
	}
	if got := call("8.8.8.8"); got != http.StatusTooManyRequests {
		t.Errorf("2nd non-WL = %d, want 429", got)
	}
}

func TestBypassSkipsOutboundGuard(t *testing.T) {
	// breaker tripped (always-fail base, MaxFailures 1): a normal request is
	// rejected, but a trusted request still reaches base.
	base := &stubRT{fn: func() (*http.Response, error) { return nil, errDown }}
	tr := New(base, Config{MaxFailures: 1, Cooldown: time.Minute})
	_, _ = tr.RoundTrip(req(t)) // trip it
	if _, err := tr.RoundTrip(req(t)); !Rejected(err) {
		t.Fatal("breaker should be open for normal requests")
	}

	r := req(t).WithContext(WithTrusted(context.Background()))
	callsBefore := base.calls.Load()
	_, err := tr.RoundTrip(r)
	if Rejected(err) {
		t.Error("trusted request must skip the open breaker")
	}
	if base.calls.Load() != callsBefore+1 {
		t.Error("trusted request must reach base.RoundTrip")
	}
}

func TestClientIPPrefersForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := ClientIP(r); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want 203.0.113.7 (leftmost XFF hop)", got)
	}
}
