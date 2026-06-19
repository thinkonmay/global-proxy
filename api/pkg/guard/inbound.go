package guard

import (
	"net/http"

	"golang.org/x/time/rate"
)

// Allowlist marks matching requests trusted — skipping ALL guard (inbound rate
// limit and the outbound breaker/bulkhead). For admin / health checks that must
// pass even while the gateway is shedding load.
func Allowlist(match Match) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if match(r) {
				r = r.WithContext(WithTrusted(r.Context()))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Denylist rejects matching requests with 403 (inbound only — a blocked client
// never reaches downstream).
func Denylist(match Match) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if match(r) {
				reject(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitConfig tunes the per-key token-bucket limiter.
type RateLimitConfig struct {
	RPS   rate.Limit // sustained tokens/sec per key
	Burst int        // bucket size (max burst)
	Key   KeyFunc    // bucket key; nil => ClientIP
}

// RateLimit token-bucket limits per key; over limit => 429. Trusted requests pass.
func RateLimit(cfg RateLimitConfig) Middleware {
	if cfg.Key == nil {
		cfg.Key = ClientIP
	}
	buckets := newRegistry(func(string) *rate.Limiter {
		return rate.NewLimiter(cfg.RPS, cfg.Burst)
	})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if trusted(r.Context()) || buckets.get(cfg.Key(r)).Allow() {
				next.ServeHTTP(w, r)
				return
			}
			reject(w, http.StatusTooManyRequests, "rate limited")
		})
	}
}

func reject(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
