package metricsingest

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

// Handler registers virtdaemon metrics push on the global gateway (mTLS at the edge).
type Handler struct {
	srv *metricsagg.Server
	pr  *postgrest.Client
}

func New(srv *metricsagg.Server, pr *postgrest.Client) *Handler {
	return &Handler{srv: srv, pr: pr}
}

func (h *Handler) Register(mux *http.ServeMux) {
	if h == nil || h.srv == nil {
		return
	}
	push := metricsagg.RequireVirtdaemonMTLS(h.push)
	router.V1(mux).POST("/metrics/push", push)
}

func (h *Handler) push(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	h.registerCluster(r, body)
	h.srv.HandlePush(w, r)
}

func (h *Handler) registerCluster(r *http.Request, body []byte) {
	if h == nil || h.pr == nil {
		return
	}
	domain := strings.TrimSpace(r.Header.Get("cluster"))
	if domain == "" {
		return
	}
	node := strings.TrimSpace(r.Header.Get("node"))

	var free *int
	if strings.TrimSpace(r.Header.Get("type")) == "info" {
		if gb, ok := cluster.FreeGBFromWorkerInfoJSON(body); ok {
			free = &gb
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := cluster.Register(ctx, h.pr, domain, node, free); err != nil {
		slog.Debug("cluster register", "domain", domain, "node", node, "err", err)
	}
}
