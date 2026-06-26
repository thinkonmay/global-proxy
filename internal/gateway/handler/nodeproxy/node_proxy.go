package nodeproxy

import (
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/clusterproxy"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
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
	v1 := router.V1(mux)
	v1.GET("/pb-proxy/snapshots", h.proxySnapshots)
	v1.POST("/pb-proxy/snapshots/restore", h.proxySnapshotsRestore)

	v1.GET("/volumes/snapshots", h.proxySnapshots)
	v1.POST("/volumes/snapshots/restore", h.proxySnapshotsRestore)
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
