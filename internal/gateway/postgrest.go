package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/guard"
)

// proxyTimeout bounds each proxied API request (TDD §2.1.1).
const proxyTimeout = 5 * time.Second

// newProxy builds a reverse proxy to rawURL over the shared circuit-breaking
// transport rt. director runs after scheme/host are rewritten, for path rewrite
// and header injection. Returns nil (route should be skipped) if rawURL is empty
// or unparseable.
func newProxy(rawURL string, rt http.RoundTripper, director func(*http.Request)) *httputil.ReverseProxy {
	if rawURL == "" {
		return nil
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		slog.Error("invalid upstream url, route disabled", "url", rawURL, "err", err)
		return nil
	}
	return &httputil.ReverseProxy{
		Transport: rt,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			if director != nil {
				director(req)
			}
		},
		ErrorHandler: proxyError,
	}
}

// proxyError maps a guard rejection to 503 {"global_unavailable":true} and any
// other upstream failure to 502 — never a hung proxy (P11).
func proxyError(w http.ResponseWriter, _ *http.Request, err error) {
	if guard.Rejected(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"global_unavailable":true}`))
		return
	}
	slog.Error("proxy error", "err", err)
	w.WriteHeader(http.StatusBadGateway)
}

// timed wraps an http.Handler with a per-request timeout context.
func timed(h http.Handler, d time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
	}
}
