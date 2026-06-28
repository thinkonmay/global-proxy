package adminhost

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/upstream"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
)

func InitGate(cfg *config.Config) (*admingate.Gate, error) {
	if !cfg.Admin.Enabled {
		return nil, nil
	}
	if cfg.Admin.Redis.URL == "" {
		return nil, fmt.Errorf("admin enabled but redis url empty")
	}
	if cfg.Admin.SigningSecret == "" {
		return nil, fmt.Errorf("admin enabled but signing secret empty")
	}
	otp, err := admingate.NewRedisOTPStore(cfg.Admin.Redis.URL)
	if err != nil {
		return nil, err
	}
	mailer := admingate.Mailer(admingate.LogMailer{})
	if cfg.Admin.Resend.APIKey != "" {
		mailer = &admingate.ResendMailer{
			APIKey: cfg.Admin.Resend.APIKey,
			From:   cfg.Admin.Resend.From,
			Client: admingate.DefaultHTTPClient(),
		}
	}
	return admingate.NewGate(admingate.Config{
		Enabled:          true,
		AllowedIPs:       cfg.Admin.AllowedIPs,
		AllowedEmails:    cfg.Admin.AllowedEmails,
		CookieDomain:     cfg.Admin.CookieDomain,
		SessionTTLHours:  cfg.Admin.SessionTTLHours,
		OTPTTLMinutes:    cfg.Admin.OTPTTLMinutes,
		SigningSecret:    cfg.Admin.SigningSecret,
		BasicAuthEnabled: cfg.Admin.BasicAuthEnabled,
		BasicAuthUser:    cfg.Admin.BasicAuthUser,
		BasicAuthPass:    cfg.Admin.BasicAuthPass,
	}, otp, otp, mailer)
}

func WrapHostRouter(public http.Handler, cfg *config.Config, gate *admingate.Gate, rt http.RoundTripper) http.Handler {
	router := admingate.NewHostRouter(cfg.Admin.Hosts.Public, public)
	if gate == nil {
		return router
	}
	// Dashboard upstreams use DefaultTransport: their HTTP 5xx (e.g. Grafana
	// /api/gnet/* marketplace proxy) must not trip the global outbound breaker.
	registerAdminHost(router, cfg.Admin.Hosts.Studio, cfg.Admin.Upstreams.Studio, gate, http.DefaultTransport)
	registerAnalyticsHost(router, cfg, gate, rt)
	registerGrafanaHost(router, cfg, gate)
	registerLitellmHost(router, cfg, gate)
	return router
}

const grafanaProxyUserHeader = "X-WEBAUTH-USER"

func registerGrafanaHost(router *admingate.HostRouter, cfg *config.Config, gate *admingate.Gate) {
	host := cfg.Admin.Hosts.Grafana
	upstreamURL := cfg.Admin.Upstreams.Grafana
	if host == "" || upstreamURL == "" {
		return
	}
	// Grafana auth.proxy user — must match security.admin_user in volumes/grafana/grafana.ini.
	proxyUser := "admin"
	proxy := upstream.NewProxy(upstreamURL, http.DefaultTransport, func(req *http.Request) {
		// Grafana is HTTP behind TLS-terminating gateway; cookie_secure needs https scheme.
		req.Header.Set("X-Forwarded-Proto", "https")
		upstream.SetForwardedHeaders(req)
		// Gateway validated SSO; do not forward Authorization (confuses Grafana auth.proxy).
		req.Header.Del("Authorization")
		req.Header.Set(grafanaProxyUserHeader, proxyUser)
	})
	if proxy == nil {
		slog.Error("admin upstream invalid", "host", host, "url", upstreamURL)
		return
	}
	upstream := newGrafanaSessionMiddleware(upstreamURL, proxyUser, proxy)
	router.Register(host, newAdminHostHandler(gate, upstream))
}

func registerLitellmHost(router *admingate.HostRouter, cfg *config.Config, gate *admingate.Gate) {
	host := cfg.Admin.Hosts.Litellm
	upstreamURL := cfg.Admin.Upstreams.Litellm
	if host == "" || upstreamURL == "" {
		return
	}
	masterKey := strings.TrimSpace(cfg.Admin.LitellmMasterKey)
	proxy := upstream.NewProxy(upstreamURL, http.DefaultTransport, func(req *http.Request) {
		upstream.SetAdminForwardedHeaders(req)
		// Gateway admin SSO replaces manual master-key entry in the LiteLLM UI.
		if masterKey != "" {
			req.Header.Set("Authorization", "Bearer "+masterKey)
		}
	}, upstream.LocationRewriteModifier(upstreamURL))
	if proxy == nil {
		slog.Error("admin upstream invalid", "host", host, "url", upstreamURL)
		return
	}
	router.Register(host, newAdminHostHandler(gate, proxy))
}

func registerAdminHost(router *admingate.HostRouter, host, upstreamURL string, gate *admingate.Gate, rt http.RoundTripper) {
	if host == "" || upstreamURL == "" {
		return
	}
	proxy := upstream.NewProxy(upstreamURL, rt, upstream.SetForwardedHeaders)
	if proxy == nil {
		slog.Error("admin upstream invalid", "host", host, "url", upstreamURL)
		return
	}
	router.Register(host, newAdminHostHandler(gate, proxy))
}

func registerAnalyticsHost(router *admingate.HostRouter, cfg *config.Config, gate *admingate.Gate, rt http.RoundTripper) {
	host := cfg.Admin.Hosts.Analytics
	if host == "" {
		return
	}
	mux := http.NewServeMux()
	gate.RegisterRoutes(mux)

	prefix := cfg.Admin.Ingest.AnalyticsPrefix
	if prefix == "" {
		prefix = "/api/"
	}
	if cfg.Admin.Upstreams.RybbitBackend != "" {
		if backend := upstream.NewProxy(cfg.Admin.Upstreams.RybbitBackend, rt, upstream.SetForwardedHeaders); backend != nil {
			mux.Handle(prefix, backend)
			if trimmed := strings.TrimSuffix(prefix, "/"); trimmed != prefix {
				mux.Handle(trimmed, backend)
			}
		}
	}
	if cfg.Admin.Upstreams.RybbitClient != "" {
		if client := upstream.NewProxy(cfg.Admin.Upstreams.RybbitClient, rt, upstream.SetForwardedHeaders); client != nil {
			mux.Handle("/", gate.ProtectUpstream(client))
		}
	}
	router.Register(host, mux)
}

func newAdminHostHandler(gate *admingate.Gate, upstream http.Handler) http.Handler {
	mux := http.NewServeMux()
	gate.RegisterRoutes(mux)
	mux.Handle("/", gate.ProtectUpstream(upstream))
	return mux
}

func RegisterInternalRoutes(mux *http.ServeMux, gate *admingate.Gate) {
	if gate == nil {
		return
	}
	h := gate.ProtectUpstream(http.HandlerFunc(serveInternalNotImplemented))
	mux.Handle("/v1/internal/", h)
}

func serveInternalNotImplemented(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"message":"internal API not implemented"}`))
}
