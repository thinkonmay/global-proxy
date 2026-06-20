package handler

import (
	"encoding/json"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

type RouteOptions struct {
	DevJobs bool
}

type Handler struct {
	bus bus.Client
}

func NewHandler(bus bus.Client) *Handler {
	return &Handler{bus: bus}
}

func (h *Handler) Route(mux *http.ServeMux) {
	h.RouteWithOptions(RouteOptions{})
}

func (h *Handler) RouteWithOptions(opts RouteOptions) {
	// caller registers on mux via main newMux — kept for compatibility
	_ = opts
}

func (h *Handler) Register(mux *http.ServeMux, opts RouteOptions) {
	mux.HandleFunc("GET /health", h.Health)
	if opts.DevJobs && h.bus != nil {
		mux.HandleFunc("POST /jobs", h.CreateJob)
	}
}

func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
