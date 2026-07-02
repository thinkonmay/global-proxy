package catalog

import (
	"context"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

func (h *Handler) CreateFeedback(w http.ResponseWriter, r *http.Request) {
	var args map[string]any
	if err := httpx.ReadJSONBody(r, &args); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	if err := h.pr.Insert(ctx, "feedbacks", args, nil); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, nil)
}
