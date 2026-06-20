package main

import (
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	"github.com/thinkonmay/global-proxy/api/pkg/supabase/auth"
)

const (
	restPrefix    = "/rest/v1"
	graphqlPath   = "/graphql/v1"
	storagePrefix = "/storage/v1"
	metaPrefix    = "/pg"
)

var removedStackMsg = []byte(`{"message":"GoTrue, Realtime, and Edge Functions are not deployed in this stack"}`)

// registerKongRoutes wires Supabase-compatible Kong service mappings (rest, graphql,
// storage, meta, studio) with key-auth, ACL, WAF, and basic-auth parity.
func registerKongRoutes(mux *http.ServeMux, cfg *config.Config, rt http.RoundTripper) {
	keys := auth.NewKeys(
		cfg.Supabase.AnonKey,
		cfg.Supabase.PublishableKey,
		cfg.Supabase.ServiceKey,
		cfg.Supabase.SecretKey,
	)
	pathWAF := guard.PathWAF(guard.PathWAFConfig{
		AllowedIPs:      cfg.WAF.AllowedIPs,
		PublicReadPaths: cfg.WAF.PublicReadPaths,
	})

	registerRemovedRoutes(mux)

	if rest := newProxy(cfg.PostgREST.URL, rt, func(req *http.Request) {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, restPrefix)
		setForwardedHeaders(req)
	}); rest != nil {
		h := pathWAF(auth.RequireKey(keys, auth.PolicyAnonAndAdmin)(timed(rest, proxyTimeout)))
		mux.Handle(restPrefix+"/", h)
	} else {
		slog.Error("postgrest url invalid, /rest/v1 disabled")
	}

	if graphql := newProxy(cfg.PostgREST.URL, rt, func(req *http.Request) {
		req.URL.Path = "/rpc/graphql"
		req.Header.Set("Content-Profile", "graphql_public")
		setForwardedHeaders(req)
	}); graphql != nil {
		h := auth.RequireKey(keys, auth.PolicyAnonAndAdmin)(timed(graphql, proxyTimeout))
		mux.Handle(graphqlPath, h)
	}

	registerStorageRoute(mux, cfg, rt, keys)

	if cfg.Upstreams.Meta != "" {
		if meta := newProxy(cfg.Upstreams.Meta, rt, func(req *http.Request) {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, metaPrefix)
			setForwardedHeaders(req)
		}); meta != nil {
			h := auth.RequireKey(keys, auth.PolicyAdminOnly)(timed(meta, proxyTimeout))
			mux.Handle(metaPrefix+"/", h)
		} else {
			slog.Error("meta upstream invalid, /pg/* disabled")
		}
	}

	registerBlockedRoutes(mux)

	// Studio is served on studio.<domain> via admin host router (B12).
}

func registerRemovedRoutes(mux *http.ServeMux) {
	for _, prefix := range []string{
		"/auth/v1/",
		"/realtime/v1/",
		"/functions/v1/",
		"/analytics/v1/",
	} {
		mux.Handle(prefix, http.HandlerFunc(serveRemovedStack))
	}
}

func registerBlockedRoutes(mux *http.ServeMux) {
	mux.Handle("/api/mcp", http.HandlerFunc(serveForbidden))
}

func serveRemovedStack(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(removedStackMsg)
}

func serveForbidden(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
}

func setForwardedHeaders(req *http.Request) {
	if req.Header.Get("X-Forwarded-For") == "" {
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			req.Header.Set("X-Forwarded-For", host)
		}
	}
	if req.Header.Get("X-Forwarded-Proto") == "" {
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
	}
	if req.Header.Get("X-Forwarded-Host") == "" {
		req.Header.Set("X-Forwarded-Host", req.Host)
	}
}
