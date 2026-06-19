package guard

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubRT is a scriptable base RoundTripper that counts calls.
type stubRT struct {
	calls atomic.Int64
	fn    func() (*http.Response, error)
}

func (s *stubRT) RoundTrip(*http.Request) (*http.Response, error) {
	s.calls.Add(1)
	return s.fn()
}

func resp(status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}
}

func req(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "http://postgrest:3000/job", nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestOpensAfterConsecutiveFailures(t *testing.T) {
	base := &stubRT{fn: func() (*http.Response, error) { return nil, fmt.Errorf("conn refused") }}
	tr := New(base, Config{MaxFailures: 3, Cooldown: time.Minute})

	for range 3 { // 3 failures -> trip
		_, _ = tr.RoundTrip(req(t))
	}
	callsBefore := base.calls.Load()

	_, err := tr.RoundTrip(req(t))
	if !Rejected(err) {
		t.Fatalf("err = %v, want open-circuit rejection", err)
	}
	if base.calls.Load() != callsBefore {
		t.Errorf("base called while open (%d -> %d): must fail fast, not hit downstream",
			callsBefore, base.calls.Load())
	}
}

func TestFiveHundredCountsButResponseStillReturned(t *testing.T) {
	base := &stubRT{fn: func() (*http.Response, error) { return resp(500), nil }}
	tr := New(base, Config{MaxFailures: 2, Cooldown: time.Minute})

	// First 500: caller still gets the real response (not an error).
	r, err := tr.RoundTrip(req(t))
	if err != nil {
		t.Fatalf("5xx should propagate as response, not error: %v", err)
	}
	if r.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", r.StatusCode)
	}

	// But 5xx counts toward the breaker: second one trips it.
	_, _ = tr.RoundTrip(req(t))
	if _, err := tr.RoundTrip(req(t)); !Rejected(err) {
		t.Errorf("breaker should be open after 2x 5xx, err = %v", err)
	}
}

func TestFourxxDoesNotTrip(t *testing.T) {
	base := &stubRT{fn: func() (*http.Response, error) { return resp(400), nil }}
	tr := New(base, Config{MaxFailures: 2, Cooldown: time.Minute})

	for range 5 {
		r, err := tr.RoundTrip(req(t))
		if err != nil || r.StatusCode != 400 {
			t.Fatalf("4xx call failed: %v status=%v", err, r)
		}
	}
	// downstream healthy (client error ≠ downstream failure) → never open.
	if _, err := tr.RoundTrip(req(t)); Rejected(err) {
		t.Error("breaker opened on 4xx, must not")
	}
}

func TestHalfOpenRecovers(t *testing.T) {
	var healthy atomic.Bool
	base := &stubRT{fn: func() (*http.Response, error) {
		if healthy.Load() {
			return resp(200), nil
		}
		return nil, fmt.Errorf("down")
	}}
	tr := New(base, Config{MaxFailures: 2, Cooldown: 50 * time.Millisecond})

	for range 2 { // trip
		_, _ = tr.RoundTrip(req(t))
	}
	if _, err := tr.RoundTrip(req(t)); !Rejected(err) {
		t.Fatal("should be open")
	}

	healthy.Store(true)
	time.Sleep(70 * time.Millisecond) // cooldown -> half-open

	r, err := tr.RoundTrip(req(t)) // probe
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("probe should pass once healthy: %v", err)
	}
	if _, err := tr.RoundTrip(req(t)); Rejected(err) {
		t.Error("breaker should be closed after successful probe")
	}
}

func TestBulkheadShedsWhenFull(t *testing.T) {
	release := make(chan struct{})
	var inBase atomic.Int64
	base := &stubRT{fn: func() (*http.Response, error) {
		inBase.Add(1)
		<-release // hold the slot until the test lets go
		return resp(200), nil
	}}
	// high MaxFailures so only the bulkhead (not the breaker) can shed here.
	tr := New(base, Config{MaxFailures: 100, Cooldown: time.Minute, MaxConcurrent: 2})
	r := req(t)

	for range 2 { // fill both slots
		go func() { _, _ = tr.RoundTrip(r) }()
	}
	for i := 0; inBase.Load() < 2; i++ { // wait until both are inside base
		if i > 1000 {
			t.Fatal("calls never reached downstream")
		}
		time.Sleep(time.Millisecond)
	}

	callsBefore := base.calls.Load()
	_, err := tr.RoundTrip(r) // 3rd: bulkhead full -> shed
	if !Rejected(err) {
		t.Fatalf("err = %v, want overloaded (fail-fast)", err)
	}
	if base.calls.Load() != callsBefore {
		t.Error("shed call still hit downstream, bulkhead leaked")
	}
	close(release)
}

func TestPerHostIsolation(t *testing.T) {
	base := &stubRT{fn: func() (*http.Response, error) { return nil, fmt.Errorf("down") }}
	tr := New(base, Config{MaxFailures: 2, Cooldown: time.Minute})

	bad, _ := http.NewRequest(http.MethodGet, "http://postgrest:3000/job", nil)
	for range 3 {
		_, _ = tr.RoundTrip(bad)
	}
	// other host must have its own (still-closed) breaker
	good, _ := http.NewRequest(http.MethodGet, "http://pocketbase:8090/x", nil)
	if _, err := tr.RoundTrip(good); Rejected(err) {
		t.Error("pocketbase breaker tripped by postgrest failures — not isolated")
	}
}
