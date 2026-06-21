package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const storeQueryTimeout = 5 * time.Second

// StoreHandler serves /v1/store/* typed REST.
type StoreHandler struct {
	pr        *postgrest.Client
	transport http.RoundTripper
}

func NewStoreHandler(pr *postgrest.Client, rt http.RoundTripper) *StoreHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &StoreHandler{pr: pr, transport: rt}
}

func (h *StoreHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/store/preorders", h.PreorderTemplate)
	mux.HandleFunc("POST /v1/store/preorders/", h.PreorderTemplate)
}

func (h *StoreHandler) PreorderTemplate(w http.ResponseWriter, r *http.Request) {
	_, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	var body struct {
		AppID int64 `json:"app_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AppID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "app_id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), storeQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "preorder_template", map[string]any{"app_id": body.AppID}, &out); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}
