package vaultproxy

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/upstream"
)

const (
	vaultPrefix  = "/vault"
	vaultTimeout = 30 * time.Second
)

// Handler proxies virtdaemon→Vault PKI calls through the public gateway (D27).
// Vault stays on the compose network; worker nodes reach it at /vault/v1/*.
type Handler struct {
	serviceKey string
	proxy      http.Handler
}

func New(vaultURL, serviceKey string, rt http.RoundTripper) *Handler {
	vaultURL = strings.TrimSpace(vaultURL)
	if vaultURL == "" {
		return nil
	}
	proxy := upstream.NewProxy(vaultURL, rt, func(req *http.Request) {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, vaultPrefix)
		upstream.SetForwardedHeaders(req)
	})
	if proxy == nil {
		slog.Error("vault upstream invalid, /vault/v1 disabled", "url", vaultURL)
		return nil
	}
	return &Handler{
		serviceKey: strings.TrimSpace(serviceKey),
		proxy:      timed(proxy, vaultTimeout),
	}
}

func timed(h http.Handler, d time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	if h == nil {
		return
	}
	mux.Handle(vaultPrefix+"/v1/", http.HandlerFunc(h.serve))
	mux.Handle(vaultPrefix+"/v1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != vaultPrefix+"/v1" {
			h.serve(w, r)
			return
		}
		http.Redirect(w, r, vaultPrefix+"/v1/", http.StatusPermanentRedirect)
	}))
	slog.Info("vault PKI proxy enabled", "prefix", vaultPrefix+"/v1/")
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid service credentials")
		return
	}
	if !allowedVaultPath(r.Method, r.URL.Path) {
		httpx.WriteError(w, http.StatusForbidden, "vault path not allowed")
		return
	}
	h.proxy.ServeHTTP(w, r)
}

func (h *Handler) requireServiceKey(r *http.Request) bool {
	if h.serviceKey == "" {
		return true
	}
	if key := strings.TrimSpace(r.Header.Get("apikey")); key == h.serviceKey {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:]) == h.serviceKey
	}
	return false
}

// allowedVaultPath restricts the proxy to virtdaemon PKI bootstrap only.
func allowedVaultPath(method, path string) bool {
	path = strings.TrimPrefix(path, vaultPrefix)
	if !strings.HasPrefix(path, "/v1/") {
		return false
	}
	switch method {
	case http.MethodPost:
		if strings.HasPrefix(path, "/v1/auth/userpass/login/") {
			return true
		}
		// POST /v1/{mount}/issue/{role}
		rest := strings.TrimPrefix(path, "/v1/")
		parts := strings.SplitN(rest, "/", 3)
		return len(parts) == 3 && parts[1] == "issue"
	case http.MethodGet:
		// GET /v1/{mount}/ca/pem
		return strings.HasSuffix(path, "/ca/pem")
	default:
		return false
	}
}
