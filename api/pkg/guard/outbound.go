package guard

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// Rejections meaning the guard blocked a call before/instead of the upstream.
var (
	ErrOpen       = errors.New("guard: circuit open")
	ErrOverloaded = errors.New("guard: host overloaded")
)

// Rejected reports a fail-fast rejection (open circuit or full bulkhead) the
// caller should map to 503 {"global_unavailable": true}.
func Rejected(err error) bool {
	return errors.Is(err, ErrOpen) || errors.Is(err, ErrOverloaded)
}

// Config tunes the per-host breaker and bulkhead.
type Config struct {
	MaxFailures   uint32        // consecutive failures (conn error, timeout, 5xx) before the breaker opens
	Cooldown      time.Duration // how long the breaker stays open before a probe
	MaxConcurrent int           // max in-flight calls per host (bulkhead); <=0 disables
}

// Transport is an http.RoundTripper with one breaker + bulkhead per target host.
type Transport struct {
	base  http.RoundTripper
	hosts *registry[*host]
}

func New(base http.RoundTripper, cfg Config) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 5
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 30 * time.Second
	}
	return &Transport{
		base:  base,
		hosts: newRegistry(func(string) *host { return newHost(cfg) }),
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if trusted(req.Context()) { // whitelisted: skip the guard
		return t.base.RoundTrip(req)
	}
	h := t.hosts.get(req.URL.Host)

	if h.slots != nil { // bulkhead: full => shed, don't queue
		select {
		case h.slots <- struct{}{}:
			defer func() { <-h.slots }()
		default:
			return nil, ErrOverloaded
		}
	}
	if !h.breaker.allow() { // circuit open => fail fast
		return nil, ErrOpen
	}

	resp, err := t.base.RoundTrip(req)
	h.breaker.record(err == nil && resp.StatusCode < 500) // 5xx is a failure, 4xx is not
	return resp, err
}

// host: per-host breaker + bulkhead slots (nil when MaxConcurrent disabled).
type host struct {
	breaker *breaker
	slots   chan struct{}
}

func newHost(cfg Config) *host {
	h := &host{breaker: &breaker{maxFailures: cfg.MaxFailures, cooldown: cfg.Cooldown}}
	if cfg.MaxConcurrent > 0 {
		h.slots = make(chan struct{}, cfg.MaxConcurrent)
	}
	return h
}

// breaker: closed → (maxFailures consecutive failures) → open for cooldown →
// one probe → closed on success / open again on failure.
type breaker struct {
	maxFailures uint32
	cooldown    time.Duration

	mu        sync.Mutex
	failures  uint32
	openUntil time.Time // zero = closed
}

// allow reports whether a call may proceed, letting one probe through when the
// cooldown ends.
func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() {
		return true
	}
	if time.Now().Before(b.openUntil) {
		return false
	}
	b.openUntil = time.Now().Add(b.cooldown) // half-open: one probe, re-block the rest
	return true
}

// record feeds the outcome back: success closes, failure counts toward opening.
func (b *breaker) record(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if success {
		b.failures = 0
		b.openUntil = time.Time{}
		return
	}
	b.failures++
	if b.failures >= b.maxFailures {
		b.openUntil = time.Now().Add(b.cooldown)
	}
}
