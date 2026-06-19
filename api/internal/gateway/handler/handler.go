package handler

import (
	"encoding/json"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// Handler serves the typed enqueue endpoints. The gateway holds no DB — it only
// publishes to the bus.
type Handler struct {
	bus bus.Client
}

func NewHandler(bus bus.Client) *Handler {
	return &Handler{bus: bus}
}

// Route registers the handler's typed endpoints on mux.
func (h *Handler) Route(mux *http.ServeMux) {
	mux.HandleFunc("POST /jobs", h.Create)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
