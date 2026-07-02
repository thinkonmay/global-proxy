package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

// CreateSubscription previously started a recurring, provider-hosted subscription.
// Recurring subscriptions have been removed; renewals are now manual via buy_plan
// (POST /v1/billing/payments). This endpoint returns 410 Gone.
// POST /v1/billing/subscriptions
func (h *Handler) CreateSubscription(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, http.StatusGone, "recurring subscriptions removed; use POST /v1/billing/payments")
}

// CancelSubscription cancels a specific machine for the authenticated user.
// machine_id is taken from the query string (?machine_id=) or request body.
// DELETE /v1/billing/subscriptions
func (h *Handler) CancelSubscription(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}

	// Accept machine_id from query string first, then fall back to JSON body.
	machineIDStr := strings.TrimSpace(r.URL.Query().Get("machine_id"))
	if machineIDStr == "" {
		var body struct {
			MachineID int64 `json:"machine_id"`
		}
		// Best-effort decode; ignore EOF (empty body).
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.MachineID > 0 {
			machineIDStr = fmt.Sprintf("%d", body.MachineID)
		}
	}
	if machineIDStr == "" {
		httpx.WriteError(w, http.StatusBadRequest, "machine_id required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	// Convert to int64 for the RPC; reuse fmt.Sscanf for simplicity.
	var machineID int64
	if _, err := fmt.Sscanf(machineIDStr, "%d", &machineID); err != nil || machineID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "machine_id must be a positive integer")
		return
	}

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "cancel_machine", map[string]any{
		"p_machine_id": machineID,
		"p_email":      email,
	}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, true)
}

// planChargeMoney resolves the fiat amount to charge for a plan in the given
// currency from the plan's per-currency catalog price (billing.plans.price ->
// {currency} = MAJOR-unit number), returning it in provider minor units. The price
// is authoritative server state; the client never supplies it. Returns an error
// if the plan is inactive/missing or has no price for the currency.
func (h *Handler) planChargeMoney(ctx context.Context, planName, currency string) (payment.Money, error) {
	currency = strings.ToUpper(strings.TrimSpace(currency))
	q := url.Values{}
	q.Set("select", "price->"+currency)
	q.Set("active", "eq.true")
	q.Set("name", "eq."+planName)
	q.Set("limit", "1")
	var rows []map[string]json.RawMessage
	if err := h.pr.SelectService(ctx, "plans", q, &rows); err != nil {
		return payment.Money{}, err
	}
	if len(rows) == 0 {
		return payment.Money{}, fmt.Errorf("plan %q not found or inactive", planName)
	}
	raw, ok := rows[0][currency]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return payment.Money{}, fmt.Errorf("plan %q has no %s price", planName, currency)
	}
	var amount float64
	if err := json.Unmarshal(raw, &amount); err != nil {
		return payment.Money{}, fmt.Errorf("plan %q malformed %s price: %w", planName, currency, err)
	}
	if amount <= 0 {
		return payment.Money{}, fmt.Errorf("plan %q has non-positive %s price", planName, currency)
	}
	return payment.FromMajor(amount, currency), nil
}

// rawJSON marshals a metadata map for buildRedirectURL; nil/empty → nil.
func rawJSON(m map[string]any) json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return b
}
