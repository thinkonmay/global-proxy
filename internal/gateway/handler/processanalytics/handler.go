// Package processanalytics ingests batched VM process rollups from virtdaemon
// and publishes them to the platform ClickHouse pipeline (not Rybbit).
package processanalytics

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const (
	publishTimeout   = 5 * time.Second
	blacklistTimeout = 10 * time.Second
	processBlacklistConstant = "process_analytics_blacklist"
)

type Handler struct {
	bus bus.Client
	pr  *postgrest.Client
}

func New(b bus.Client, pr *postgrest.Client) *Handler {
	if b == nil {
		return nil
	}
	return &Handler{bus: b, pr: pr}
}

func (h *Handler) Register(mux *http.ServeMux) {
	if h == nil {
		return
	}
	push := metricsagg.RequireVirtdaemonMTLS(h.push)
	blacklist := metricsagg.RequireVirtdaemonMTLS(h.blacklist)
	router.V1(mux).POST("/analytics/process/push", push)
	router.V1(mux).GET("/analytics/process/blacklist", blacklist)
}

type pushBody struct {
	UserEmail        string    `json:"user_email"`
	RuntimeSessionID string    `json:"runtime_session_id"`
	FlushReason      string    `json:"flush_reason"`
	FlushSeq         uint64    `json:"flush_seq"`
	EventTime        time.Time `json:"event_time"`
	Apps             []appRow  `json:"apps"`
}

type appRow struct {
	AppKey      string  `json:"app_key"`
	DurationSec float64 `json:"duration_sec"`
	LaunchCount uint32  `json:"launch_count"`
}

func (h *Handler) push(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req pushBody
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.UserEmail = strings.TrimSpace(req.UserEmail)
	req.RuntimeSessionID = strings.TrimSpace(req.RuntimeSessionID)
	if req.UserEmail == "" || req.RuntimeSessionID == "" {
		http.Error(w, "user_email and runtime_session_id required", http.StatusBadRequest)
		return
	}
	if len(req.Apps) == 0 {
		http.Error(w, "apps required", http.StatusBadRequest)
		return
	}

	cluster := strings.TrimSpace(r.Header.Get("cluster"))
	node := strings.TrimSpace(r.Header.Get("node"))
	if cluster == "" {
		http.Error(w, "cluster header required", http.StatusBadRequest)
		return
	}

	eventTime := req.EventTime
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}
	flushReason := strings.TrimSpace(req.FlushReason)
	if flushReason == "" {
		flushReason = "interval"
	}

	ctx, cancel := context.WithTimeout(r.Context(), publishTimeout)
	defer cancel()

	for _, app := range req.Apps {
		appKey := strings.TrimSpace(app.AppKey)
		if appKey == "" || app.DurationSec <= 0 {
			continue
		}
		msg := model.AppUsageMsg{
			EventTime:        eventTime,
			UserEmail:        req.UserEmail,
			RuntimeSessionID: req.RuntimeSessionID,
			AppKey:           appKey,
			DurationSec:      app.DurationSec,
			LaunchCount:      app.LaunchCount,
			Cluster:          cluster,
			Node:             node,
			FlushReason:      flushReason,
			FlushSeq:         req.FlushSeq,
			Source:           "process_analytics",
		}
		if err := bus.Publish(ctx, h.bus, model.TopicAppUsage, msg); err != nil {
			slog.Warn("analytics process push publish", "err", err, "user", req.UserEmail, "session", req.RuntimeSessionID)
			http.Error(w, "publish failed", http.StatusServiceUnavailable)
			return
		}
	}

	w.WriteHeader(http.StatusAccepted)
}

type constantRow struct {
	Value json.RawMessage `json:"value"`
}

func (h *Handler) blacklist(w http.ResponseWriter, r *http.Request) {
	if h.pr == nil {
		http.Error(w, "postgrest not configured", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), blacklistTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("name", "eq."+processBlacklistConstant)
	q.Set("select", "value")
	q.Set("limit", "1")

	var rows []constantRow
	if err := h.pr.SelectService(ctx, "constant", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	if len(rows) == 0 || len(rows[0].Value) == 0 {
		http.Error(w, "blacklist not configured", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rows[0].Value)
}
