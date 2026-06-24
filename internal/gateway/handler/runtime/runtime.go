package runtime

import (
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/clusterproxy"
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
	routes := []struct {
		method       string
		path         string
		upstream     string
		requireUser  bool
		sse          bool
	}{
		{http.MethodGet, "/v1/runtime/info", "/info", true, false},
		{http.MethodPost, "/v1/runtime/new", "/new", true, false},
		{http.MethodGet, "/v1/runtime/new/sse", "/new/sse", false, true},
		{http.MethodDelete, "/v1/runtime/close", "/close", true, false},
		{http.MethodPost, "/v1/runtime/restart", "/restart", true, false},
		{http.MethodPost, "/v1/runtime/reallocate", "/reallocate", true, false},
		{http.MethodGet, "/v1/runtime/reallocate/sse", "/reallocate/sse", false, true},
		{http.MethodPost, "/v1/runtime/template", "/template", true, false},
		{http.MethodGet, "/v1/runtime/template/sse", "/template/sse", false, true},
		{http.MethodPost, "/v1/runtime/resize", "/resize", true, false},
		{http.MethodPost, "/v1/runtime/assistant", "/assistant", true, false},
		{http.MethodPost, "/v1/runtime/snapshots", "/snapshots", true, false},
		{http.MethodDelete, "/v1/runtime/resource", "/resource", true, false},
		{http.MethodGet, "/v1/runtime/log", "/log", true, false},
		{http.MethodGet, "/v1/runtime/analytics", "/analytics", true, false},
	}
	for _, route := range routes {
		h.register(mux, route.method, route.path, route.upstream, route.requireUser, route.sse)
	}
}

func (h *Handler) register(mux *http.ServeMux, method, path, upstream string, requireUser, sse bool) {
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
	mux.HandleFunc(method+" "+path, fn)
}
