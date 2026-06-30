package catalog

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/superuser"
)

func (h *Handler) CheckSuperuser(w http.ResponseWriter, r *http.Request) {
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
	email, ok, status, msg := auth.RequireUser(r.Context(), r, nil)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(req.Email)) {
		httpx.WriteError(w, http.StatusForbidden, "email mismatch")
		return
	}
	isSuper, err := superuser.IsEmail(r.Context(), h.pr, email)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"isSuperuser": isSuper})
}

func (h *Handler) PatchStoreCodeName(w http.ResponseWriter, r *http.Request) {
	storeID := strings.TrimSpace(r.PathValue("storeID"))
	if storeID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "store id required")
		return
	}
	var req struct {
		CodeName string `json:"code_name"`
	}
	if err := httpx.ReadJSONBody(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.CodeName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Missing code_name")
		return
	}
	email, ok, status, msg := auth.RequireUser(r.Context(), r, nil)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	isSuper, err := superuser.IsEmail(r.Context(), h.pr, email)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !isSuper {
		httpx.WriteError(w, http.StatusForbidden, "Unauthorized: Not a superuser")
		return
	}

	sanitized := sanitizeCodeName(req.CodeName)
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("id", "eq."+storeID)
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
