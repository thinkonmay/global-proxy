package pwa

import (
	"context"
	"net/http"
	"net/url"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

// Volumes returns owned volume metadata from global Postgres (not daemon Info templates).
func (h *Handler) Volumes(w http.ResponseWriter, r *http.Request) {
	usr, code, msg := auth.PWAAuthFromRequest(r.Context(), h.transport, r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("select", "local_id,configuration,snapshot_enabled,metadata")
	q.Set("user", "eq."+usr.Email)
	var rows []map[string]any
	if err := h.pr.SelectService(ctx, "volumes", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	httpx.WriteData(w, rows)
}
