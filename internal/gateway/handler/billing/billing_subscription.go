package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

// CreateSubscription starts a recurring, provider-hosted subscription for a plan.
// It creates a pending local subscription row, then opens the provider checkout and returns
// its redirect URL. The provider subscription id is linked back on the activation webhook.
// POST /v1/billing/subscriptions
func (h *Handler) CreateSubscription(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	// NOTE: no Amount field — the charge price is resolved server-side from the
	// plan (planChargeMoney). Any client-sent "amount" is silently dropped by the
	// JSON decoder, which is intentional: the client must not influence the price.
	var body struct {
		PlanName      string         `json:"plan_name"`
		ClusterDomain string         `json:"cluster_domain"`
		Template      *string        `json:"template"`
		Provider      string         `json:"provider"`
		Currency      string         `json:"currency"`
		Interval      string         `json:"interval"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.PlanName == "" || body.ClusterDomain == "" || body.Provider == "" || body.Currency == "" {
		httpx.WriteError(w, http.StatusBadRequest, "plan_name, cluster_domain, provider, and currency required")
		return
	}
	if h.registry == nil {
		httpx.WriteError(w, http.StatusInternalServerError, "payment registry not configured")
		return
	}
	client, found := h.registry.Get(body.Provider)
	if !found {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported provider")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), billingDepositTimeout)
	defer cancel()

	// Create the pending subscription intent; its id correlates the activation webhook.
	template := "win11"
	if body.Template != nil && *body.Template != "" {
		template = *body.Template
	}
	var subID int64
	if err := h.pr.RPC(ctx, "create_subscription_intent", map[string]any{
		"p_email":          email,
		"p_plan_name":      body.PlanName,
		"p_cluster_domain": body.ClusterDomain,
		"p_template":       template,
	}, &subID); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	// Resolve the charge amount SERVER-SIDE from the plan's per-currency catalog
	// price. The client-supplied body.Amount is never trusted — otherwise a buyer
	// could post amount=0.01 and receive a full-priced subscription.
	money, err := h.planChargeMoney(ctx, body.PlanName, body.Currency)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	sub, err := client.Subscribe(ctx, payment.SubscribeParams{
		IdempotencyKey: strconv.FormatInt(subID, 10),
		Money:          money,
		Interval:       body.Interval,
		PlanRef:        body.PlanName,
		CustomerEmail:  email,
		Description:    body.PlanName,
		ReturnURL:      returnURLForMetadata(rawJSON(body.Metadata)),
	})
	if err != nil {
		if errors.Is(err, payment.ErrNotSupported) {
			httpx.WriteError(w, http.StatusBadRequest, "provider does not support subscriptions")
			return
		}
		httpx.WriteUpstreamErr(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"subscription_id": subID,
			"redirect_url":    sub.RedirectURL,
		},
	})
}

// CancelSubscription cancels the auto-renew provider subscription of the authenticated user.
// The provider's cancellation webhook settles the local status. DELETE /v1/billing/subscriptions
func (h *Handler) CancelSubscription(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	// Find the caller's active auto-renew subscription (user column holds the email).
	var rows []struct {
		Provider      string `json:"provider"`
		ProviderSubID string `json:"provider_sub_id"`
	}
	q := url.Values{}
	q.Set("select", "provider,provider_sub_id")
	q.Set("user", "eq."+email)
	q.Set("provider_sub_id", "not.is.null")
	q.Set("cancelled_at", "is.null")
	q.Set("order", "id.desc")
	q.Set("limit", "1")
	if err := h.pr.SelectService(ctx, "subscriptions", q, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	if len(rows) == 0 || rows[0].ProviderSubID == "" {
		httpx.WriteError(w, http.StatusNotFound, "no active subscription")
		return
	}
	if h.registry == nil {
		httpx.WriteError(w, http.StatusInternalServerError, "payment registry not configured")
		return
	}
	client, found := h.registry.Get(rows[0].Provider)
	if !found {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported provider")
		return
	}
	if err := client.CancelSubscription(ctx, rows[0].ProviderSubID); err != nil {
		if errors.Is(err, payment.ErrNotSupported) {
			httpx.WriteError(w, http.StatusBadRequest, "provider does not support subscriptions")
			return
		}
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, true)
}

// planChargeMoney resolves the fiat amount to charge for a plan in the given
// currency from the plan's per-currency catalog price (billing.plans.price ->
// {currency} -> {amount, tag}), returning it in provider minor units. The price
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
	var val struct {
		Amount float64 `json:"amount"`
	}
	if err := json.Unmarshal(raw, &val); err != nil {
		return payment.Money{}, fmt.Errorf("plan %q malformed %s price: %w", planName, currency, err)
	}
	if val.Amount <= 0 {
		return payment.Money{}, fmt.Errorf("plan %q has non-positive %s price", planName, currency)
	}
	return payment.FromMajor(val.Amount, currency), nil
}

// rawJSON marshals a metadata map for returnURLForMetadata; nil/empty → nil.
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
