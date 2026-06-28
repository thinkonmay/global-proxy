package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/adminhost"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/cors"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/billing"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/cdp"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/clusterrouting"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/catalog"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/files"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/gamification"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/grant"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/jobs"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/logingest"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/mail"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/metricsingest"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/processanalytics"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/noderuntime"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/ota"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/persona"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/pwa"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/runtime"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/store"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/vaultproxy"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/volume"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/webhook"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/sse"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/upstream"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	corazawaf "github.com/thinkonmay/global-proxy/api/pkg/waf/coraza"
)

const (
	rateRPS   = 50
	rateBurst = 100
)

var ipBlacklist = []string{}

func newMux(
	h *handler.Handler,
	hub *sse.Hub,
	catalogH *catalog.Handler,
	otaH *ota.Handler,
	gamificationH *gamification.Handler,
	billingH *billing.Handler,
	storeH *store.Handler,
	grants *grant.Handler,
	filesH *files.Handler,
	runtimeH *runtime.Handler,
	personaHTTP *persona.Handler,
	nodeRuntime *noderuntime.Handler,
	vaultProxy *vaultproxy.Handler,
	pwaH *pwa.Handler,
	volumeH *volume.Handler,
	mailH *mail.Handler,
	jobsH *jobs.Handler,
	metricsIngest *metricsingest.Handler,
	processAnalytics *processanalytics.Handler,
	cdpHTTP *cdp.Handler,
	logIngest *logingest.Handler,
	routingHTTP *clusterrouting.Handler,
	cfg *config.Config,
	rt http.RoundTripper,
	coraza *corazawaf.Middleware,
	gate *admingate.Gate,
	payReg *registry.Registry,
	eventBus bus.Client,
) http.Handler {
	mux := http.NewServeMux()

	h.Register(mux)
	volumeH.Register(mux)
	if mailH != nil {
		mailH.Register(mux)
	}
	if jobsH != nil {
		jobsH.Register(mux)
	}
	if metricsIngest != nil {
		metricsIngest.Register(mux)
	}
	if processAnalytics != nil {
		processAnalytics.Register(mux)
	}
	if cdpHTTP != nil {
		cdpHTTP.Register(mux)
	}
	if logIngest != nil {
		logIngest.Register(mux)
	}
	if routingHTTP != nil {
		routingHTTP.Register(mux)
	}
	catalogH.Register(mux)
	otaH.Register(mux)
	gamificationH.Register(mux)
	billingH.Register(mux)
	storeH.Register(mux)
	pwaH.Register(mux)
	grants.Register(mux)
	filesH.Register(mux)
	runtimeH.Register(mux)
	personaHTTP.Register(mux)
	nodeRuntime.Register(mux)
	if vaultProxy != nil {
		vaultProxy.Register(mux)
	}
	webhook.RegisterPaymentWebhooks(mux, payReg, eventBus)

	// SSE: one authenticated stream per user; clients filter on msg.type / ids.
	// Per-resource paths are aliases that pre-filter the same hub (OpenAPI parity).
	sseHandler := func(w http.ResponseWriter, r *http.Request) {
		auth.PromoteQueryToken(r)
		email, ok, status, msg := auth.RequireUser(r.Context(), r, rt)
		if !ok {
			auth.WriteAuthErr(w, status, msg)
			return
		}
		hub.ServeFor(w, r, email)
	}
	paymentSSE := func(w http.ResponseWriter, r *http.Request) {
		auth.PromoteQueryToken(r)
		email, ok, status, msg := auth.RequireUser(r.Context(), r, rt)
		if !ok {
			auth.WriteAuthErr(w, status, msg)
			return
		}
		txnID := strings.TrimSpace(r.PathValue("transactionId"))
		hub.ServeForFiltered(w, r, email, "payment", func(data json.RawMessage) bool {
			if txnID == "" {
				return true
			}
			var p struct {
				TransactionID string `json:"transaction_id"`
			}
			if json.Unmarshal(data, &p) != nil {
				return false
			}
			return p.TransactionID == txnID
		})
	}
	jobSSE := func(w http.ResponseWriter, r *http.Request) {
		auth.PromoteQueryToken(r)
		email, ok, status, msg := auth.RequireUser(r.Context(), r, rt)
		if !ok {
			auth.WriteAuthErr(w, status, msg)
			return
		}
		jobID := strings.TrimSpace(r.PathValue("jobId"))
		hub.ServeForFiltered(w, r, email, "job", func(data json.RawMessage) bool {
			if jobID == "" {
				return true
			}
			var p struct {
				JobID int64 `json:"job_id"`
			}
			if json.Unmarshal(data, &p) != nil {
				return false
			}
			return fmt.Sprint(p.JobID) == jobID
		})
	}
	v1 := router.V1(mux)
	v1.GET("/sse", sseHandler)
	v1.GET("/payments/{transactionId}/events", paymentSSE)
	v1.GET("/jobs/{jobId}/events", jobSSE)
	mux.HandleFunc("GET /sse", sseHandler) // legacy alias for pre-/v1 clients

	adminhost.RegisterInternalRoutes(mux, gate)
	if gate != nil {
		gate.RegisterPublicAccessRoutes(mux)
	}
	upstream.RegisterRybbitIngest(mux, cfg, rt)
	upstream.RegisterKong(mux, cfg, rt)

	chain := []guard.Middleware{
		guard.Denylist(guard.IPSet(ipBlacklist...)),
		cors.Middleware(cfg),
		guard.Allowlist(guard.IPSet(cfg.WAF.AllowedIPs...)),
		guard.RateLimit(guard.RateLimitConfig{RPS: rateRPS, Burst: rateBurst}),
	}
	if coraza != nil {
		chain = append([]guard.Middleware{coraza.AsGuard()}, chain...)
	}
	routes := http.Handler(mux)
	if website := upstream.NewProxy(cfg.Upstreams.Website, rt, upstream.SetForwardedHeaders); website != nil {
		routes = upstream.WrapWebsiteFallback(routes, website)
	}
	public := guard.Chain(routes, chain...)
	hostRouter := adminhost.WrapHostRouter(public, cfg, gate, rt)
	// All virtual hosts (public, analytics, studio, grafana) need CORS — admin hosts
	// bypass the public middleware chain, and Rybbit ingest is cross-origin until the
	// PWA loads script.js from the public host (first-party proxy).
	return cors.Middleware(cfg)(hostRouter)
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
