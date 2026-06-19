package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
)

// restPrefix is the Supabase-compatible REST path the gateway proxies to PostgREST.
const restPrefix = "/rest/v1"

// restProxyTimeout bounds each proxied request (TDD §2.1.1).
const restProxyTimeout = 5 * time.Second

// registerRestProxy wires a transparent /rest/v1/* reverse proxy to PostgREST.
// It strips the prefix and injects the anon key when the client sent none — the
// lean replacement for Kong's anon role mapping (P0-A). rt is the shared
// circuit-breaking transport.
func registerRestProxy(mux *http.ServeMux, cfg config.PostgREST, rt http.RoundTripper) {
	target, err := url.Parse(cfg.URL)
	if err != nil {
		slog.Error("invalid postgrest url, /rest/v1 proxy disabled", "err", err)
		return
	}

	proxy := &httputil.ReverseProxy{
		Transport: rt, // circuit breaker shared with the typed PostgREST client
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.URL.Path = strings.TrimPrefix(req.URL.Path, restPrefix)

			// Inject anon credentials only when the client supplied none.
			if cfg.AnonKey != "" && req.Header.Get("apikey") == "" {
				req.Header.Set("apikey", cfg.AnonKey)
				req.Header.Set("Authorization", "Bearer "+cfg.AnonKey)
			}
		},
		// Guard rejection / downstream error => 503, never a hung proxy (P11).
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			if guard.Rejected(err) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"global_unavailable":true}`))
				return
			}
			slog.Error("rest proxy error", "err", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	mux.HandleFunc(restPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), restProxyTimeout)
		defer cancel()
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}
