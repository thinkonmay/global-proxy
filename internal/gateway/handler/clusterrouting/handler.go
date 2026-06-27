package clusterrouting

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/routingagg"
	ssewire "github.com/thinkonmay/global-proxy/api/pkg/sse"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// WatchHub broadcasts routing revision events to connected master daemons (SSE).
type WatchHub struct {
	mu      sync.RWMutex
	clients map[chan model.ClusterRoutingUpdatedMsg]struct{}
}

func NewWatchHub() *WatchHub {
	return &WatchHub{clients: make(map[chan model.ClusterRoutingUpdatedMsg]struct{})}
}

func (h *WatchHub) Subscribe() (<-chan model.ClusterRoutingUpdatedMsg, func()) {
	ch := make(chan model.ClusterRoutingUpdatedMsg, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	unsub := func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
		close(ch)
	}
	return ch, unsub
}

func (h *WatchHub) Broadcast(msg model.ClusterRoutingUpdatedMsg) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}

// Handler exposes cluster routing sync/snapshot/watch for virtdaemon masters.
type Handler struct {
	store *routingagg.Store
	bus   bus.Client
	watch *WatchHub
}

func New(store *routingagg.Store, eventBus bus.Client, watch *WatchHub) *Handler {
	return &Handler{store: store, bus: eventBus, watch: watch}
}

func (h *Handler) InitSubscriptions() {
	if h == nil || h.bus == nil || h.watch == nil {
		return
	}
	bus.Subscribe(h.bus, model.TopicClusterRoutingUpdated, "gateway-cluster-routing", func(_ context.Context, msg model.ClusterRoutingUpdatedMsg) error {
		h.watch.Broadcast(msg)
		return nil
	})
}

func (h *Handler) Register(mux *http.ServeMux) {
	if h == nil || h.store == nil {
		return
	}
	v1 := router.V1(mux)
	mtls := metricsagg.RequireVirtdaemonMTLS
	v1.POST("/cluster/routing/sync", mtls(h.sync))
	v1.GET("/cluster/routing/snapshot", mtls(h.snapshot))
	v1.GET("/cluster/routing/events", mtls(h.events))
}

type syncRequest struct {
	Records []cluster.RoutingEntry `json:"records"`
}

func (h *Handler) sync(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.Header.Get("cluster"))
	if domain == "" {
		http.Error(w, "cluster header required", http.StatusBadRequest)
		return
	}
	var req syncRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	result, err := cluster.SyncRouting(ctx, h.store, domain, req.Records)
	if err != nil {
		slog.Debug("cluster routing sync", "domain", domain, "err", err)
		http.Error(w, "sync failed", http.StatusBadGateway)
		return
	}
	if result.Changed && h.bus != nil {
		_ = bus.Publish(r.Context(), h.bus, model.TopicClusterRoutingUpdated, model.ClusterRoutingUpdatedMsg{
			Domain:   result.Domain,
			Revision: result.Revision,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (h *Handler) snapshot(w http.ResponseWriter, r *http.Request) {
	exclude := strings.TrimSpace(r.URL.Query().Get("exclude"))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	clusters, err := cluster.ListRouting(ctx, h.store, exclude)
	if err != nil {
		http.Error(w, "snapshot failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"clusters": clusters})
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	if h.watch == nil {
		http.Error(w, "watch unavailable", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ssewire.WriteHeaders(w)
	ch, unsub := h.watch.Subscribe()
	defer unsub()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	idx := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			idx++
			if err := ssewire.WriteEvent(w, idx, msg); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			_, _ = io.WriteString(w, ":keepalive\n\n")
			flusher.Flush()
		}
	}
}
