package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const personaReadTimeout = 5 * time.Second

type PersonaHandler struct {
	pr        *postgrest.Client
	transport http.RoundTripper
}

func NewPersonaHandler(pr *postgrest.Client, rt http.RoundTripper) *PersonaHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &PersonaHandler{pr: pr, transport: rt}
}

func (h *PersonaHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/persona", h.GetPersona)
	mux.HandleFunc("GET /v1/persona/recommendations", h.GetRecommendations)
}

func (h *PersonaHandler) GetPersona(w http.ResponseWriter, r *http.Request) {
	auth, code, msg := pwaAuthFromRequest(r.Context(), h.transport, r, r.URL.Query().Get("issuer"))
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), personaReadTimeout)
	defer cancel()
	profile, err := persona.FetchProfile(ctx, h.pr, strings.ToLower(auth.Email))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persona unavailable"})
		return
	}
	if profile == nil {
		writeJSON(w, http.StatusOK, map[string]any{"profile": nil})
		return
	}
	var decoded any
	_ = json.Unmarshal(profile, &decoded)
	writeJSON(w, http.StatusOK, map[string]any{"profile": decoded})
}

func (h *PersonaHandler) GetRecommendations(w http.ResponseWriter, r *http.Request) {
	auth, code, msg := pwaAuthFromRequest(r.Context(), h.transport, r, r.URL.Query().Get("issuer"))
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), personaReadTimeout)
	defer cancel()
	recs, err := persona.FetchRecommendations(ctx, h.pr, strings.ToLower(auth.Email))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persona unavailable"})
		return
	}
	if recs == nil {
		writeJSON(w, http.StatusOK, map[string]any{"recommendations": []any{}})
		return
	}
	var decoded any
	_ = json.Unmarshal(recs, &decoded)
	writeJSON(w, http.StatusOK, map[string]any{"recommendations": decoded})
}
