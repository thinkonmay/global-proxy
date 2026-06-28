package runtime

import (
	"context"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/daemonclient"
	runtimepkg "github.com/thinkonmay/global-proxy/api/pkg/runtime"
	"github.com/thinkonmay/global-proxy/api/pkg/sse"
	"github.com/thinkonmay/global-proxy/api/pkg/volumeconfig"
	"github.com/thinkonmay/thinkshare-daemon/persistent"
)

func (h *Handler) streamNew(w http.ResponseWriter, r *http.Request, prepared *runtimepkg.PrepareResult) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream, err := h.cfg.Daemon.NewStream(ctx, prepared.ClusterID, prepared.Session)
	if err != nil {
		runtimepkg.RollbackLeases(ctx, h.cfg.PostgREST, prepared.Session)
		httpx.WriteError(w, http.StatusBadGateway, "new stream unavailable")
		return
	}
	if err := daemonclient.RelayNewStream(ctx, w, stream, prepared.VolumeIDs); err != nil {
		runtimepkg.RollbackLeases(ctx, h.cfg.PostgREST, prepared.Session)
	}
}

func (h *Handler) streamReallocate(w http.ResponseWriter, r *http.Request, clusterID int64, email string, req *persistent.AllocateRequest) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream, err := h.cfg.Daemon.AllocateStream(ctx, clusterID, req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "allocate stream unavailable")
		return
	}
	finished, _ := daemonclient.RelayAllocateStream(ctx, w, stream)
	if finished && req != nil && req.Destination != nil && req.Source != nil {
		_ = volumeconfig.SetTemplateSource(ctx, h.cfg.PostgREST, email, req.Destination.Name, req.Source.Name)
	}
}

func (h *Handler) streamTemplate(w http.ResponseWriter, r *http.Request, clusterID int64, rename *persistent.RenameRequest, allocate *persistent.AllocateRequest) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	_ = daemonclient.RelayTemplateStream(ctx, w, h.cfg.Daemon, clusterID, rename, allocate)
}

func writeReallocateFinishedSSE(w http.ResponseWriter) {
	sse.WriteHeaders(w)
	_ = sse.WriteEvent(w, 1, map[string]any{"finished": true})
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
}
