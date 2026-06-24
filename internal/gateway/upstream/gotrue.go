package upstream

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
)

const (
	authPrefix       = "/auth/v1"
	authProxyTimeout = 15 * time.Second
)

// authRateLimit is tighter than the global edge (credential stuffing / brute-force).
var authRateLimit = guard.RateLimitConfig{RPS: 10, Burst: 20}

// registerGoTrueRoute proxies public /auth/v1/* to internal Kong (D28 / Track C1).
// Traffic MUST NOT bypass Kong to reach GoTrue directly.
// Returns true when the route was registered.
func registerGoTrueRoute(mux *http.ServeMux, cfg *config.Config, rt http.RoundTripper) bool {
	raw := strings.TrimSpace(cfg.Upstreams.Kong)
	if raw == "" {
		raw = strings.TrimSpace(cfg.Upstreams.GoTrue) // backward compat
	}
	if raw == "" {
		return false
	}
	if isDirectGoTrueUpstream(raw) {
		slog.Error("auth proxy disabled: upstream must be internal Kong (http://kong:8000), not GoTrue directly",
			"url", raw)
		return false
	}

	proxy := NewProxy(raw, rt, func(req *http.Request) {
		// Kong auth-v1 route expects the full /auth/v1/... path (strip_path on Kong side).
		SetForwardedHeaders(req)
	})
	if proxy == nil {
		slog.Error("kong auth proxy url invalid, /auth/v1 disabled", "url", raw)
		return false
	}

	chain := guard.Chain(
		timed(proxy, authProxyTimeout),
		authAuditLog,
		guard.RateLimit(authRateLimit),
	)

	mux.Handle(authPrefix+"/", chain)
	mux.Handle(authPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != authPrefix {
			chain.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, authPrefix+"/", http.StatusPermanentRedirect)
	}))

	slog.Info("auth proxy enabled via internal Kong", "upstream", raw)
	return true
}

func isDirectGoTrueUpstream(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "auth" || strings.HasPrefix(host, "supabase-auth")
}

func authAuditLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("auth_proxy",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"forwarded_for", r.Header.Get("X-Forwarded-For"),
			"user_agent", r.Header.Get("User-Agent"),
		)
		next.ServeHTTP(w, r)
	})
}
