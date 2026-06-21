package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
)

func initAdminGate(cfg *config.Config) (*admingate.Gate, error) {
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

func wrapHostRouter(public http.Handler, cfg *config.Config, gate *admingate.Gate, rt http.RoundTripper) http.Handler {
	router := admingate.NewHostRouter(cfg.Admin.Hosts.Public, public)
	if gate == nil {
		return router
	}
	// Dashboard upstreams use DefaultTransport: their HTTP 5xx (e.g. Grafana
	// /api/gnet/* marketplace proxy) must not trip the global outbound breaker.
	registerAdminHost(router, cfg.Admin.Hosts.Studio, cfg.Admin.Upstreams.Studio, gate, http.DefaultTransport)
	registerAnalyticsHost(router, cfg, gate, rt)
	registerGrafanaHost(router, cfg, gate)
	return router
}

const grafanaProxyUserHeader = "X-WEBAUTH-USER"

// grafanaSessionCookies are set by Grafana after auth.proxy login-token minting on /login.
var grafanaSessionCookies = []string{"grafana_session", "grafana_sess"}

func registerGrafanaHost(router *admingate.HostRouter, cfg *config.Config, gate *admingate.Gate) {
	host := cfg.Admin.Hosts.Grafana
	upstreamURL := cfg.Admin.Upstreams.Grafana
	if host == "" || upstreamURL == "" {
		return
	}
	// Grafana auth.proxy user — must match security.admin_user in volumes/grafana/grafana.ini.
	proxyUser := "admin"
	proxy := newProxy(upstreamURL, http.DefaultTransport, func(req *http.Request) {
		// Grafana is HTTP behind TLS-terminating gateway; cookie_secure needs https scheme.
		req.Header.Set("X-Forwarded-Proto", "https")
		setForwardedHeaders(req)
		// Gateway validated SSO; do not forward Authorization (confuses Grafana auth.proxy).
		req.Header.Del("Authorization")
		req.Header.Set(grafanaProxyUserHeader, proxyUser)
	})
	if proxy == nil {
		slog.Error("admin upstream invalid", "host", host, "url", upstreamURL)
		return
	}
	upstream := wrapGrafanaSessionBootstrap(proxy)
	router.Register(host, newAdminHostHandler(gate, upstream))
}

// wrapGrafanaSessionBootstrap redirects browser GETs to /login until Grafana sets
// grafana_session. With enable_login_token, the cookie is minted on /login (not /).
// Without this, auth.proxy authenticates API calls but the SPA has no session token
// and POST /api/user/auth-tokens/rotate loops with 401 "user token not found".
func wrapGrafanaSessionBootstrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldBootstrapGrafanaSession(r) {
			target := "/login"
			if q := r.URL.RawQuery; q != "" {
				target += "?" + q
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func shouldBootstrapGrafanaSession(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	path := r.URL.Path
	switch {
	case path == "/login":
		return false
	case strings.HasPrefix(path, "/public/"):
		return false
	case strings.HasPrefix(path, "/avatar/"):
		return false
	case strings.HasPrefix(path, "/api/"):
		return false
	case strings.HasPrefix(path, "/apis/"):
		return false
	}
	return !hasGrafanaSessionCookie(r)
}

func hasGrafanaSessionCookie(r *http.Request) bool {
	for _, name := range grafanaSessionCookies {
		if _, err := r.Cookie(name); err == nil {
			return true
		}
	}
	return false
}

func registerAdminHost(router *admingate.HostRouter, host, upstreamURL string, gate *admingate.Gate, rt http.RoundTripper) {
	if host == "" || upstreamURL == "" {
		return
	}
	proxy := newProxy(upstreamURL, rt, setForwardedHeaders)
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
		if backend := newProxy(cfg.Admin.Upstreams.RybbitBackend, rt, setForwardedHeaders); backend != nil {
			mux.Handle(prefix, backend)
			if trimmed := strings.TrimSuffix(prefix, "/"); trimmed != prefix {
				mux.Handle(trimmed, backend)
			}
		}
	}
	if cfg.Admin.Upstreams.RybbitClient != "" {
		if client := newProxy(cfg.Admin.Upstreams.RybbitClient, rt, setForwardedHeaders); client != nil {
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

func registerInternalAdminRoutes(mux *http.ServeMux, gate *admingate.Gate) {
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
