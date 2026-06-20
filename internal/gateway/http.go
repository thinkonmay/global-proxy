package main

import (
	"net/http"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
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
	prCfg config.PostgREST,
	up config.Upstreams,
	rt http.RoundTripper,
) http.Handler {
	mux := http.NewServeMux()

	h.Register(mux, handler.RouteOptions{DevJobs: devJobs})
	globalRPC.Register(mux)
	grants.Register(mux)

	mux.HandleFunc("GET /sse", hub.Serve)

	registerRestProxy(mux, prCfg, rt)
	registerUpstreams(mux, up, rt)

	return guard.Chain(mux,
		guard.Denylist(guard.IPSet(ipBlacklist...)),
		withCORS,
		guard.Allowlist(guard.IPSet(ipWhitelist...)),
		guard.RateLimit(guard.RateLimitConfig{RPS: rateRPS, Burst: rateBurst}),
	)
}
