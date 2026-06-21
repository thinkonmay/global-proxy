package main

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/config"
)

// rybbitIngestExactPaths are first-party analytics ingest routes proxied on the
// public gateway host so the PWA loads script.js and posts /track same-origin.
var rybbitIngestExactPaths = []string{
	"/api/track",
	"/api/identify",
	"/api/script.js",
}

// rybbitIngestPrefixPaths are prefix-matched ingest routes (tracking config, replay).
var rybbitIngestPrefixPaths = []string{
	"/api/site/tracking-config/",
	"/api/session-replay/",
}

func registerRybbitIngestRoutes(mux *http.ServeMux, cfg *config.Config, rt http.RoundTripper) {
	upstream := strings.TrimSpace(cfg.Admin.Upstreams.RybbitBackend)
	if upstream == "" {
		return
	}
	proxy := newProxy(upstream, rt, setForwardedHeaders)
	if proxy == nil {
		slog.Error("rybbit ingest proxy disabled", "url", upstream)
		return
	}
	for _, path := range rybbitIngestExactPaths {
		mux.Handle(path, proxy)
	}
	for _, prefix := range rybbitIngestPrefixPaths {
		mux.Handle(prefix, proxy)
	}
}
