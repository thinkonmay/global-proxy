package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

func (h *Handler) Wallet(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_pocket_balance", map[string]any{"email": email}, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *Handler) Subscription(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_subscription_v3", map[string]any{"email": email}, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *Handler) Domains(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_domains_availability_v5", map[string]any{}, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

// pmRow mirrors the billing.card columns returned to the client.
type pmRow struct {
	ID          int64  `json:"id"`
	Provider    string `json:"provider"`
	CustomerRef string `json:"customer_ref"`
	PmRef       string `json:"pm_ref"`
	Brand       string `json:"brand"`
	Last4       string `json:"last4"`
	ExpMonth    int    `json:"exp_month"`
	ExpYear     int    `json:"exp_year"`
	IsDefault   bool   `json:"is_default"`
}

// appUserRow is a minimal projection of identity.app_user used to resolve email → id.
type appUserRow struct {
	ID int64 `json:"id"`
}

// Cards lists the saved payment methods for the authenticated user.
// GET /v1/billing/cards
// Requires live DB — flagged for integration verification.
func (h *Handler) Cards(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	// Resolve email → user_id via identity.app_user.
	var users []appUserRow
	uq := url.Values{}
	uq.Set("select", "id")
	uq.Set("email", "eq."+email)
	uq.Set("limit", "1")
	if err := h.pr.SelectService(ctx, "users", uq, &users); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	if len(users) == 0 {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	userID := users[0].ID

	var rows []pmRow
	q := url.Values{}
	q.Set("select", "id,provider,customer_ref,pm_ref,brand,last4,exp_month,exp_year,is_default")
	q.Set("user_id", "eq."+strconv.FormatInt(userID, 10))
	if err := h.pr.SelectService(ctx, "card", q, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

// resolveUserID looks up the caller's numeric user id from the "users" view by email.
// It returns an error (and writes the response) when the user is not found.
func (h *Handler) resolveUserID(ctx context.Context, email string) (int64, error) {
	var users []appUserRow
	uq := url.Values{}
	uq.Set("select", "id")
	uq.Set("email", "eq."+email)
	uq.Set("limit", "1")
	if err := h.pr.SelectService(ctx, "users", uq, &users); err != nil {
		return 0, err
	}
	if len(users) == 0 {
		return 0, fmt.Errorf("user not found")
	}
	return users[0].ID, nil
}
