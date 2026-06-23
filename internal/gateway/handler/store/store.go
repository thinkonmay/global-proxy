package store

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const storeQueryTimeout = 5 * time.Second

// Handler serves /v1/store/* typed REST.
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
	mux.HandleFunc("POST /v1/store/preorders", h.PreorderTemplate)
	mux.HandleFunc("POST /v1/store/preorders/", h.PreorderTemplate)
}

func (h *Handler) PreorderTemplate(w http.ResponseWriter, r *http.Request) {
	_, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	var body struct {
		AppID int64 `json:"app_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AppID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "app_id required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), storeQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "preorder_template", map[string]any{"app_id": body.AppID}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}
