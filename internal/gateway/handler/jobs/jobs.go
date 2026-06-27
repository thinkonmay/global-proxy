package jobs

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

const jobsQueryTimeout = 5 * time.Second

// Handler serves /v1/jobs/* (async provisioning history).
type Handler struct {
	pr        *postgrest.Client
	transport http.RoundTripper
}

func New(pr *postgrest.Client, rt http.RoundTripper) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Handler{pr: pr, transport: rt}
}

func (h *Handler) Register(mux *http.ServeMux) {
	router.V1(mux).GET("/jobs/history", h.History)
}

// History wraps get_job_history for poll fallback when SSE is unavailable.
func (h *Handler) History(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	onlyPending := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("only_pending")), "true")

	ctx, cancel := context.WithTimeout(r.Context(), jobsQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "get_job_history", map[string]any{
		"email":        email,
		"only_pending": onlyPending,
	}, &out); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	if len(out) == 0 {
		out = json.RawMessage("[]")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
