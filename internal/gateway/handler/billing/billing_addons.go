package billing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func (h *Handler) AddonCharges(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "list_addon_charges_v2", map[string]any{"input_email": email}, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *Handler) ListActiveAddons(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_active_addons", map[string]any{"email": email}, &rows); err != nil {
		if isNoActiveSubscriptionErr(err) {
			httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": json.RawMessage("[]")})
			return
		}
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func isNoActiveSubscriptionErr(err error) bool {
	if pe, ok := errors.AsType[*postgrest.Error](err); ok {
		return strings.Contains(string(pe.Body), "email do not have any subscription")
	}
	return strings.Contains(err.Error(), "email do not have any subscription")
}

func (h *Handler) SubscribeAddon(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	var body struct {
		AddonID int64 `json:"addon_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AddonID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "addon_id required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "subscribe_addon", map[string]any{
		"email":    email,
		"addon_id": body.AddonID,
	}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}

func (h *Handler) UnsubscribeAddon(w http.ResponseWriter, r *http.Request) {
	addonID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("addonId")), 10, 64)
	if err != nil || addonID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid addon id")
		return
	}
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "unsubscribe_addon", map[string]any{
		"email":    email,
		"addon_id": addonID,
	}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}

func (h *Handler) PayAddonCharges(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var discard json.RawMessage
	if err := h.pr.RPC(ctx, "pay_all_addon_charges", map[string]any{"email": email}, &discard); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, true)
}
