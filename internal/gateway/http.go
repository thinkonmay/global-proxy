package main

import (
	"fmt"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler"
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
	globalRPC *handler.GlobalRPCHandler,
	grants *handler.GrantHandler,
	devJobs bool,
	cfg *config.Config,
	rt http.RoundTripper,
	coraza *corazawaf.Middleware,
) http.Handler {
	mux := http.NewServeMux()

	h.Register(mux, handler.RouteOptions{DevJobs: devJobs})
	globalRPC.Register(mux)
	grants.Register(mux)

	mux.HandleFunc("GET /sse", hub.Serve)

	registerKongRoutes(mux, cfg, rt)

	chain := []guard.Middleware{
		guard.Denylist(guard.IPSet(ipBlacklist...)),
		withCORS,
		guard.Allowlist(guard.IPSet(ipWhitelist...)),
		guard.RateLimit(guard.RateLimitConfig{RPS: rateRPS, Burst: rateBurst}),
	}
	if coraza != nil {
		chain = append([]guard.Middleware{coraza.AsGuard()}, chain...)
	}
	return guard.Chain(mux, chain...)
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
