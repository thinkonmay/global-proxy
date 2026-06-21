package main

import (
	"fmt"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	corazawaf "github.com/thinkonmay/global-proxy/api/pkg/waf/coraza"
)

const (
	rateRPS   = 50
	rateBurst = 100
)

var (
	ipWhitelist = []string{}
	ipBlacklist = []string{}
)

func newMux(
	h *handler.Handler,
	hub *SSEHub,
	catalog *handler.CatalogHandler,
	ota *handler.OTAHandler,
	gamification *handler.GamificationHandler,
	billing *handler.BillingHandler,
	store *handler.StoreHandler,
	grants *handler.GrantHandler,
	files *handler.FilesHandler,
	nodeProxy *handler.NodeProxyHandler,
	personaHTTP *handler.PersonaHandler,
	nodeRuntime *handler.NodeRuntimeHandler,
	pwa *handler.PWAHandler,
	devJobs bool,
	cfg *config.Config,
	rt http.RoundTripper,
	coraza *corazawaf.Middleware,
	gate *admingate.Gate,
) http.Handler {
	mux := http.NewServeMux()

	h.Register(mux, handler.RouteOptions{DevJobs: devJobs})
	catalog.Register(mux)
	ota.Register(mux)
	gamification.Register(mux)
	billing.Register(mux)
	store.Register(mux)
	pwa.Register(mux)
	grants.Register(mux)
	files.Register(mux)
	nodeProxy.Register(mux)
	personaHTTP.Register(mux)
	nodeRuntime.Register(mux)

	mux.HandleFunc("GET /sse", hub.Serve)

	registerInternalAdminRoutes(mux, gate)
	if gate != nil {
		gate.RegisterPublicAccessRoutes(mux)
	}
	registerRybbitIngestRoutes(mux, cfg, rt)
	registerKongRoutes(mux, cfg, rt)

	chain := []guard.Middleware{
		guard.Denylist(guard.IPSet(ipBlacklist...)),
		corsMiddleware(cfg),
		guard.Allowlist(guard.IPSet(ipWhitelist...)),
		guard.RateLimit(guard.RateLimitConfig{RPS: rateRPS, Burst: rateBurst}),
	}
	if coraza != nil {
		chain = append([]guard.Middleware{coraza.AsGuard()}, chain...)
	}
	routes := http.Handler(mux)
	if website := newProxy(cfg.Upstreams.Website, rt, setForwardedHeaders); website != nil {
		routes = wrapWebsiteFallback(routes, website)
	}
	public := guard.Chain(routes, chain...)
	router := wrapHostRouter(public, cfg, gate, rt)
	// All virtual hosts (public, analytics, studio, grafana) need CORS — admin hosts
	// bypass the public middleware chain, and Rybbit ingest is cross-origin until the
	// PWA loads script.js from the public host (first-party proxy).
	return corsMiddleware(cfg)(router)
}

func initCoraza(cfg config.Coraza) (*corazawaf.Middleware, error) {
	m, err := corazawaf.New(corazawaf.Config{
		Enabled:          cfg.Enabled,
		OWASPCRS:         cfg.OWASPCRS,
		RequestBodyLimit: cfg.RequestBodyLimit,
		SkipPaths:        cfg.SkipPaths,
	})
	if err != nil {
		return nil, fmt.Errorf("coraza waf: %w", err)
	}
	return m, nil
}
