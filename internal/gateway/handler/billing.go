package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const (
	billingQueryTimeout  = 5 * time.Second
	billingDepositTimeout = 30 * time.Second
)

// BillingHandler serves /v1/billing/* typed REST (replaces /v1/rpc billing RPCs).
type BillingHandler struct {
	pr        *postgrest.Client
	payment   *payment.Service
	transport http.RoundTripper
}

func NewBillingHandler(pr *postgrest.Client, rt http.RoundTripper, pay *payment.Service) *BillingHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &BillingHandler{pr: pr, payment: pay, transport: rt}
}

func (h *BillingHandler) Register(mux *http.ServeMux) {
	routes := []struct {
		method string
		path   string
		fn     http.HandlerFunc
	}{
		{http.MethodGet, "/v1/billing/wallet", h.Wallet},
		{http.MethodGet, "/v1/billing/subscription", h.Subscription},
		{http.MethodGet, "/v1/billing/addon-charges", h.AddonCharges},
		{http.MethodGet, "/v1/billing/addons", h.ListActiveAddons},
		{http.MethodPost, "/v1/billing/addons", h.SubscribeAddon},
		{http.MethodDelete, "/v1/billing/addons/{addonId}", h.UnsubscribeAddon},
		{http.MethodGet, "/v1/billing/domains", h.Domains},
		{http.MethodPost, "/v1/billing/deposits", h.CreateDeposit},
		{http.MethodGet, "/v1/billing/deposits/{transactionId}", h.DepositStatus},
		{http.MethodDelete, "/v1/billing/deposits/{transactionId}", h.CancelDeposit},
		{http.MethodPost, "/v1/billing/payments", h.CreatePayment},
		{http.MethodPost, "/v1/billing/addon-charges/pay", h.PayAddonCharges},
		{http.MethodPost, "/v1/billing/discount-codes/validate", h.ValidateDiscount},
	}
	for _, route := range routes {
		mux.HandleFunc(route.method+" "+route.path, route.fn)
		mux.HandleFunc(route.method+" "+route.path+"/", route.fn)
	}
}

func (h *BillingHandler) Wallet(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_pocket_balance", map[string]any{"email": email}, &rows); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *BillingHandler) Subscription(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_subscription_v3", map[string]any{"email": email}, &rows); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *BillingHandler) AddonCharges(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "list_addon_charges_v2", map[string]any{"input_email": email}, &rows); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *BillingHandler) ListActiveAddons(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_active_addons", map[string]any{"email": email}, &rows); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *BillingHandler) SubscribeAddon(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	var body struct {
		AddonID int64 `json:"addon_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AddonID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "addon_id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "subscribe_addon", map[string]any{
		"email":    email,
		"addon_id": body.AddonID,
	}, &out); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (h *BillingHandler) UnsubscribeAddon(w http.ResponseWriter, r *http.Request) {
	addonID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("addonId")), 10, 64)
	if err != nil || addonID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid addon id"})
		return
	}
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "unsubscribe_addon", map[string]any{
		"email":    email,
		"addon_id": addonID,
	}, &out); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (h *BillingHandler) Domains(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_domains_availability_v5", map[string]any{}, &rows); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *BillingHandler) CreateDeposit(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	var body struct {
		Amount       float64        `json:"amount"`
		Currency     string         `json:"currency"`
		Provider     string         `json:"provider"`
		Metadata     map[string]any `json:"metadata"`
		DiscountCode string         `json:"discount_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if body.Amount <= 0 || body.Currency == "" || body.Provider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "amount, currency, and provider required"})
		return
	}
	if body.DiscountCode == "" {
		body.DiscountCode = "unknown"
	}
	if body.Metadata == nil {
		body.Metadata = map[string]any{}
	}

	ctx, cancel := context.WithTimeout(r.Context(), billingDepositTimeout)
	defer cancel()

	var result json.RawMessage
	if err := h.pr.RPC(ctx, "create_pocket_deposit_v4", map[string]any{
		"email":         email,
		"amount":        body.Amount,
		"currency":      body.Currency,
		"provider":      body.Provider,
		"metadata":      body.Metadata,
		"discount_code": body.DiscountCode,
	}, &result); err != nil {
		writeBillingErr(w, err)
		return
	}
	if h.payment != nil {
		enriched, err := h.payment.EnrichDepositResult(ctx, result)
		if err != nil {
			writeBillingErr(w, err)
			return
		}
		result = enriched
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": result})
}

func (h *BillingHandler) DepositStatus(w http.ResponseWriter, r *http.Request) {
	_, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	txID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("transactionId")), 10, 64)
	if err != nil || txID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid transaction id"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "get_transaction_status", map[string]any{"id": txID}, &out); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": out})
}

func (h *BillingHandler) CancelDeposit(w http.ResponseWriter, r *http.Request) {
	_, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	txID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("transactionId")), 10, 64)
	if err != nil || txID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid transaction id"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "cancel_transaction", map[string]any{"id": txID}, &out); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (h *BillingHandler) CreatePayment(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	var body struct {
		PlanName      string  `json:"plan_name"`
		ClusterDomain string  `json:"cluster_domain"`
		Template      *string `json:"template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if body.PlanName == "" || body.ClusterDomain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "plan_name and cluster_domain required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), billingDepositTimeout)
	defer cancel()

	var discard json.RawMessage
	if err := h.pr.RPC(ctx, "pay_all_addon_charges", map[string]any{"email": email}, &discard); err != nil {
		writeBillingErr(w, err)
		return
	}
	args := map[string]any{
		"email":           email,
		"plan_name":       body.PlanName,
		"cluster_domain":  body.ClusterDomain,
	}
	if body.Template != nil {
		args["template"] = *body.Template
	}
	if err := h.pr.RPC(ctx, "create_or_replace_payment", args, &discard); err != nil {
		writeBillingErr(w, err)
		return
	}
	if err := h.pr.RPC(ctx, "verify_all_payment_v2", map[string]any{}, &discard); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": true})
}

func (h *BillingHandler) PayAddonCharges(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var discard json.RawMessage
	if err := h.pr.RPC(ctx, "pay_all_addon_charges", map[string]any{"email": email}, &discard); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": true})
}

func (h *BillingHandler) ValidateDiscount(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	var body struct {
		Code         string `json:"code"`
		DiscountCode string `json:"discount_code"`
		ApplyForType string `json:"apply_for_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		code = strings.TrimSpace(body.DiscountCode)
	}
	if code == "" || body.ApplyForType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code and apply_for_type required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "validate_discount_code", map[string]any{
		"discount_code":  code,
		"apply_for_type": body.ApplyForType,
		"user_email":     email,
	}, &rows); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func writeBillingErr(w http.ResponseWriter, err error) {
	var pe *postgrest.Error
	if errors.As(err, &pe) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": strings.TrimSpace(string(pe.Body))})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}
