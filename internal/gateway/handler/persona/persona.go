package persona

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const personaReadTimeout = 5 * time.Second

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
	mux.HandleFunc("GET /v1/persona", h.GetPersona)
	mux.HandleFunc("GET /v1/persona/recommendations", h.GetRecommendations)
}

func (h *Handler) GetPersona(w http.ResponseWriter, r *http.Request) {
	usr, code, msg := auth.PWAAuthFromRequest(r.Context(), h.transport, r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), personaReadTimeout)
	defer cancel()
	profile, err := persona.FetchProfile(ctx, h.pr, strings.ToLower(usr.Email))
	if err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "persona unavailable")
		return
	}
	if profile == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"profile": nil})
		return
	}
	var decoded any
	_ = json.Unmarshal(profile, &decoded)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"profile": decoded})
}

func (h *Handler) GetRecommendations(w http.ResponseWriter, r *http.Request) {
	usr, code, msg := auth.PWAAuthFromRequest(r.Context(), h.transport, r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), personaReadTimeout)
	defer cancel()
	recs, err := persona.FetchRecommendations(ctx, h.pr, strings.ToLower(usr.Email))
	if err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "persona unavailable")
		return
	}
	if recs == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"recommendations": []any{}})
		return
	}
	var decoded any
	_ = json.Unmarshal(recs, &decoded)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"recommendations": decoded})
}
