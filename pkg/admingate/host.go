package admingate

import (
	"net"
	"net/http"
	"strings"
)

// HostRouter dispatches requests by Host header to admin or public handlers.
type HostRouter struct {
	publicHost string
	public     http.Handler
	byHost     map[string]http.Handler
}

// NewHostRouter builds a host-based dispatcher. Unknown hosts receive 404.
func NewHostRouter(publicHost string, public http.Handler) *HostRouter {
	return &HostRouter{
		publicHost: strings.ToLower(strings.TrimSpace(publicHost)),
		public:     public,
		byHost:     make(map[string]http.Handler),
	}
}

// Register mounts handler for an admin hostname (e.g. studio.thinkmay.net).
func (r *HostRouter) Register(host string, handler http.Handler) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || handler == nil {
		return
	}
	r.byHost[host] = handler
}

func (r *HostRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := hostOnly(req.Host)
	if h, ok := r.byHost[host]; ok {
		h.ServeHTTP(w, req)
		return
	}
	if host == r.publicHost || r.publicHost == "" {
		r.public.ServeHTTP(w, req)
		return
	}
	http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
}

func hostOnly(hostport string) string {
	hostport = strings.ToLower(strings.TrimSpace(hostport))
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}
