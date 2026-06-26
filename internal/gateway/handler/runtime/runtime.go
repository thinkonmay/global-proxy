package runtime

import (
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/clusterproxy"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

// Handler proxies node runtime REST (PocketBase /info, /new, …) with GoTrue auth at the gateway edge.
type Handler struct {
	clusterSecret string
	transport     http.RoundTripper
}

func New(clusterSecret string, rt http.RoundTripper) *Handler {
	return &Handler{
		clusterSecret: clusterSecret,
		transport:     rt,
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
		h.register(v1, route.method, route.path, route.upstream, route.requireUser, route.sse)
	}
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
