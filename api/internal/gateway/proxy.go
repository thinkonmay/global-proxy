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

	"github.com/labstack/echo/v4"
)

// restPrefix is the Supabase-compatible REST path the gateway proxies to PostgREST.
const restPrefix = "/rest/v1"

// restProxyTimeout bounds each proxied request (TDD §2.1.1).
const restProxyTimeout = 5 * time.Second

// RegisterRestProxy wires a transparent /rest/v1/* reverse proxy to PostgREST.
// It strips the prefix and injects the anon key when the client sent none —
// the lean replacement for Kong's anon role mapping (P0-A).
func RegisterRestProxy(e *echo.Echo, cfg config.PostgREST) {
	target, err := url.Parse(cfg.URL)
	if err != nil {
		slog.Error("invalid postgrest url, /rest/v1 proxy disabled", "err", err)
		return
	}

	proxy := &httputil.ReverseProxy{
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
	}

	handler := func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), restProxyTimeout)
		defer cancel()
		proxy.ServeHTTP(c.Response(), c.Request().WithContext(ctx))
		return nil
	}

	e.Any(restPrefix+"/*", handler)
}
