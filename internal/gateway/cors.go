package main

import (
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
)

// Supabase/Kong parity — Studio cross-origin uploads (incl. TUS resumable) need these.
const corsAllowHeaders = "Authorization, Content-Type, apikey, x-client-info, x-upsert, range, x-requested-with, accept, accept-profile, content-profile, prefer, x-forwarded-host, x-forwarded-for, upload-length, upload-offset, upload-metadata, tus-resumable, x-http-method-override"

const corsAllowMethods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"

const corsExposeHeaders = "Content-Range, range, x-supabase-api-version, Authorization, Content-Type, Location, Tus-Extension, Tus-Max-Size, Tus-Resumable, Tus-Version, Upload-Concat, Upload-Defer-Length, Upload-Length, Upload-Metadata, Upload-Offset, Upload-Expires, X-Forwarded-Host, X-Forwarded-Proto"

var corsHeaderKeys = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Credentials",
	"Access-Control-Allow-Headers",
	"Access-Control-Allow-Methods",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
}

// stripUpstreamCORS removes CORS headers from an upstream response so the gateway
// sets a single Allow-Origin (avoids "*, https://studio..." duplicate values).
func stripUpstreamCORS(h http.Header) {
	for _, k := range corsHeaderKeys {
		h.Del(k)
	}
}

func buildAllowedOrigins(cfg *config.Config) map[string]struct{} {
	allowed := make(map[string]struct{})
	if cfg == nil {
		return allowed
	}
	httpsPort := cfg.TLS.HTTPSPort
	if httpsPort == "" {
		httpsPort = "443"
	}
	httpPort := cfg.TLS.HTTPPort
	if httpPort == "" {
		httpPort = "80"
	}
	addHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if httpsPort == "443" {
			allowed["https://"+host] = struct{}{}
		} else {
			allowed["https://"+host+":"+httpsPort] = struct{}{}
		}
		if httpPort != "80" {
			allowed["http://"+host+":"+httpPort] = struct{}{}
		}
	}
	for _, h := range cfg.TLS.Hosts {
		addHost(h)
	}
	if u := strings.TrimSpace(cfg.Gateway.PublicURL); u != "" {
		allowed[strings.TrimRight(u, "/")] = struct{}{}
	}
	return allowed
}

func corsMiddleware(cfg *config.Config) guard.Middleware {
	allowed := buildAllowedOrigins(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			if origin := r.Header.Get("Origin"); origin != "" {
				if _, ok := allowed[origin]; ok {
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Access-Control-Allow-Credentials", "true")
				}
			}
			h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
			h.Set("Access-Control-Allow-Methods", corsAllowMethods)
			h.Set("Access-Control-Expose-Headers", corsExposeHeaders)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
