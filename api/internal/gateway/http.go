package main

import (
	"net/http"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
)

// inbound rate-limit defaults (per client IP). Promote to config when tuned.
const (
	rateRPS   = 50  // sustained req/s per client
	rateBurst = 100 // burst allowance
)

// Inbound IP policy (populate from config/env later). Whitelisted IPs are marked
// trusted and skip ALL guard (rate limit + outbound breaker/bulkhead); blacklisted
// IPs get 403.
var (
	ipWhitelist = []string{} // e.g. "127.0.0.1", "10.0.0.0/8" — admin / health checks
	ipBlacklist = []string{}
)

// newMux builds the gateway router on the stdlib ServeMux (Go 1.22 method+path
// patterns). rt is the circuit-breaking transport for the /rest/v1 proxy.
func newMux(h *handler.Handler, prCfg config.PostgREST, rt http.RoundTripper) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	h.Route(mux)
	// Job status is read through the /rest/v1 proxy (GET /rest/v1/processed_message).

	// Supabase-compatible REST passthrough to PostgREST (P0-A).
	registerRestProxy(mux, prCfg, rt)

	// Inbound guard chain (outermost first): deny blacklisted IPs → CORS/preflight
	// → mark whitelisted IPs trusted → per-IP rate limit (skips trusted).
	return guard.Chain(mux,
		guard.Denylist(guard.IPSet(ipBlacklist...)),
		withCORS,
		guard.Allowlist(guard.IPSet(ipWhitelist...)),
		guard.RateLimit(guard.RateLimitConfig{RPS: rateRPS, Burst: rateBurst}),
	)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Headers", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
