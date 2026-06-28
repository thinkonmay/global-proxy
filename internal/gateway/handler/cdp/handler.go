package cdp

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

var eventKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

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
	if h == nil || h.pr == nil {
		return
	}
	router.V1(mux).POST("/analytics/cdp/event", h.appendEvent)
}

type appendBody struct {
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

// appendEvent dual-writes high-intent product events to Postgres (Rybbit ingest stays client-side).
func (h *Handler) appendEvent(w http.ResponseWriter, r *http.Request) {
	usr, code, msg := auth.PWAAuthFromRequest(r.Context(), h.transport, r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req appendBody
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if !eventKindPattern.MatchString(kind) {
		http.Error(w, "invalid kind", http.StatusBadRequest)
		return
	}
	payload := req.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	email := strings.ToLower(strings.TrimSpace(usr.Email))
	var eventID int64
	if err := h.pr.RPC(r.Context(), "append_cdp_event", map[string]any{
		"p_email":   email,
		"p_source":  "web",
		"p_kind":    kind,
		"p_payload": payload,
	}, &eventID); err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "cdp event unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": eventID})
}
