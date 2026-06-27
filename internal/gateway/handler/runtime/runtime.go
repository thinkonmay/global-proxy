package runtime

import (
	"context"
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/clusterproxy"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/daemonclient"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

const infoTimeout = 20 * time.Second

// Handler serves node runtime REST at /v1/runtime/*.
// GET /runtime/info uses mTLS gRPC when a daemon client is configured (D25/D26).
type Handler struct {
	clusterSecret string
	transport     http.RoundTripper
	daemon        *daemonclient.Client
}

func New(clusterSecret string, rt http.RoundTripper, daemon *daemonclient.Client) *Handler {
	return &Handler{
		clusterSecret: clusterSecret,
		transport:     rt,
		daemon:        daemon,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	v1 := router.V1(mux)
	routes := []struct {
		method      string
		path        string
		upstream    string
		requireUser bool
		sse         bool
	}{
		{http.MethodGet, "/runtime/info", "/info", true, false},
		{http.MethodPost, "/runtime/new", "/new", true, false},
		{http.MethodGet, "/runtime/new/sse", "/new/sse", false, true},
		{http.MethodDelete, "/runtime/close", "/close", true, false},
		{http.MethodPost, "/runtime/restart", "/restart", true, false},
		{http.MethodPost, "/runtime/reallocate", "/reallocate", true, false},
		{http.MethodGet, "/runtime/reallocate/sse", "/reallocate/sse", false, true},
		{http.MethodPost, "/runtime/template", "/template", true, false},
		{http.MethodGet, "/runtime/template/sse", "/template/sse", false, true},
		{http.MethodPost, "/runtime/resize", "/resize", true, false},
		{http.MethodPost, "/runtime/assistant", "/assistant", true, false},
		{http.MethodPost, "/runtime/snapshots", "/snapshots", true, false},
		{http.MethodDelete, "/runtime/resource", "/resource", true, false},
		{http.MethodGet, "/runtime/log", "/log", true, false},
		{http.MethodGet, "/runtime/analytics", "/analytics", true, false},
	}
	for _, route := range routes {
		if route.path == "/runtime/info" && h.daemon != nil {
			v1.Handle(route.method, route.path, h.handleInfoGRPC)
			continue
		}
		h.register(v1, route.method, route.path, route.upstream, route.requireUser, route.sse)
	}
}

func (h *Handler) handleInfoGRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpx.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), infoTimeout)
	defer cancel()
	info, err := h.daemon.InfoForUser(ctx, email)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "daemon info unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, info)
}

func (h *Handler) register(g *router.Group, method, path, upstream string, requireUser, sse bool) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		timeout := clusterproxy.DefaultTimeout * time.Second
		if sse {
			timeout = 0
		}
		clusterproxy.Forward(w, r, clusterproxy.ForwardOpts{
			UpstreamPath:  upstream,
			RequireUser:   requireUser,
			ClusterSecret: h.clusterSecret,
			Timeout:       timeout,
			Transport:     h.transport,
		})
	}
	g.Handle(method, path, fn)
}
