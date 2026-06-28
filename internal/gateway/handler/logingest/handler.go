package logingest

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	eslog "github.com/thinkonmay/global-proxy/api/pkg/logingest"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

// Handler ingests virtdaemon worker log pushes into Elasticsearch.
type Handler struct {
	client *eslog.Client
}

func New(client *eslog.Client) *Handler {
	if client == nil || !client.Enabled() {
		return nil
	}
	return &Handler{client: client}
}

func (h *Handler) Register(mux *http.ServeMux) {
	if h == nil {
		return
	}
	push := metricsagg.RequireVirtdaemonMTLS(h.Push)
	router.V1(mux).POST("/logs/push", push)
}

// Push ingests one worker log NDJSON batch (exported for tests).
func (h *Handler) Push(w http.ResponseWriter, r *http.Request) {
	h.push(w, r)
}

func (h *Handler) push(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.Header.Get("node"))
	if node == "" {
		http.Error(w, "missing node header", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.client.IndexNDJSON(ctx, body); err != nil {
		slog.Error("worker log push", "node", node, "err", err)
		http.Error(w, "index failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
