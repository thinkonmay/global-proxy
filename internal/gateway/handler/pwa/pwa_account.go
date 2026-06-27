package pwa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

func (h *Handler) IsSuperuser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := httpx.ReadJSONBody(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Email == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Missing email")
		return
	}
	usr, code, msg := auth.PWAAuthFromRequest(r.Context(), h.transport, r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	if c, m := auth.PWAEmailMatch(usr, req.Email); c != 0 {
		httpx.WriteError(w, c, m)
		return
	}
	ok, err := h.isSuperuserEmail(r.Context(), req.Email)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"isSuperuser": ok})
}

func (h *Handler) UpdateCodeName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID    json.Number `json:"app_id"`
		CodeName string      `json:"code_name"`
	}
	if err := httpx.ReadJSONBody(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.CodeName == "" || req.AppID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Missing app_id or code_name")
		return
	}
	usr, code, msg := auth.PWAAuthFromRequest(r.Context(), h.transport, r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	ok, err := h.isSuperuserEmail(r.Context(), usr.Email)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		httpx.WriteError(w, http.StatusForbidden, "Unauthorized: Not a superuser")
		return
	}

	sanitized := sanitizeCodeName(req.CodeName)
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("id", "eq."+req.AppID.String())
	if err := h.pr.Update(ctx, "stores", q, map[string]any{"code_name": sanitized}, nil); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"success": true, "code_name": sanitized})
}

func sanitizeCodeName(raw string) string {
	s := strings.ToLower(raw)
	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func quoteInFilter(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, fmt.Sprintf("%q", v))
	}
	return strings.Join(quoted, ",")
}
