package nodeproxy

import (
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/clusterproxy"
)

// Handler forwards snapshot operations to node PocketBase routes.
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
	mux.HandleFunc("GET /v1/pb-proxy/snapshots", h.proxySnapshots)
	mux.HandleFunc("POST /v1/pb-proxy/snapshots/restore", h.proxySnapshotsRestore)

	mux.HandleFunc("GET /v1/volumes/snapshots", h.proxySnapshots)
	mux.HandleFunc("POST /v1/volumes/snapshots/restore", h.proxySnapshotsRestore)
}

func (h *Handler) proxySnapshots(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/snapshots")
}

func (h *Handler) proxySnapshotsRestore(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/snapshots/restore")
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, pbPath string) {
	clusterproxy.Forward(w, r, clusterproxy.ForwardOpts{
		UpstreamPath:  pbPath,
		RequireUser:   true,
		ClusterSecret: h.clusterSecret,
		Timeout:       clusterproxy.DefaultTimeout * time.Second,
		Transport:     h.transport,
	})
}
