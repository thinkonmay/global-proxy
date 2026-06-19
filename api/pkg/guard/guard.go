// Package guard protects the gateway in both directions with one small toolkit:
//   - inbound: middleware (Allowlist, Denylist, RateLimit) that gate requests.
//   - outbound: Transport, a per-host circuit breaker + bulkhead for upstream calls.
//
// A request whitelisted inbound is marked trusted in its context and skips the
// outbound guard too. Fail-fast rejections map to 4xx / 503 (see Rejected).
package guard

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Match tests whether a request belongs to a set (e.g. an IP allow/deny list).
type Match func(*http.Request) bool

// Middleware decorates an http.Handler.
type Middleware func(http.Handler) http.Handler

// KeyFunc derives a rate-limit bucket key (default ClientIP).
type KeyFunc func(*http.Request) string

// Chain wraps h with mws, outermost first (mws[0] runs first).
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

type trustKey struct{}

// WithTrusted marks ctx as guard-exempt: inbound RateLimit and the outbound
// breaker + bulkhead all skip it. Set by Allowlist, read by RateLimit / Transport.
func WithTrusted(ctx context.Context) context.Context {
	return context.WithValue(ctx, trustKey{}, true)
}

func trusted(ctx context.Context) bool {
	v, _ := ctx.Value(trustKey{}).(bool)
	return v
}

// ClientIP is the leftmost X-Forwarded-For hop, else the remote IP (no port).
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

// IPSet matches a request's ClientIP against IPs / CIDRs (invalid entries ignored).
func IPSet(entries ...string) Match {
	var ips []net.IP
	var nets []*net.IPNet
	for _, e := range entries {
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
		} else if ip := net.ParseIP(e); ip != nil {
			ips = append(ips, ip)
		}
	}
	return func(r *http.Request) bool {
		ip := net.ParseIP(ClientIP(r))
		if ip == nil {
			return false
		}
		for _, a := range ips {
			if a.Equal(ip) {
				return true
			}
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
}
