package runtime

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

const volumesQueryTimeout = 5 * time.Second

func (h *Handler) handleListVolumes(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.cfg.Transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), volumesQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("select", "local_id,configuration,snapshot_enabled,metadata")
	q.Set("user", "eq."+email)
	var rows []map[string]any
	if err := h.cfg.PostgREST.SelectService(ctx, "volumes", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	httpx.WriteData(w, rows)
}
