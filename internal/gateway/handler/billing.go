package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const (
	billingQueryTimeout   = 5 * time.Second
	billingDepositTimeout = 30 * time.Second
)

// BillingHandler serves /v1/billing/* typed REST (replaces /v1/rpc billing RPCs).
type BillingHandler struct {
	pr        *postgrest.Client
	registry  *registry.Registry
	rates     *payment.RateService
	transport http.RoundTripper
}

func NewBillingHandler(pr *postgrest.Client, rt http.RoundTripper, reg *registry.Registry, rates *payment.RateService) *BillingHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &BillingHandler{pr: pr, registry: reg, rates: rates, transport: rt}
}

// txnRow mirrors the transactions table columns used by billing.
type txnRow struct {
	ID       int64           `json:"id"`
	Email    string          `json:"email"`
	Amount   float64         `json:"amount"`
	Currency string          `json:"currency"`
	Provider string          `json:"provider"`
	Data     json.RawMessage `json:"data"`
	Metadata json.RawMessage `json:"metadata"`
	ExpireAt string          `json:"expire_at"`
}

func dataIsEmpty(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	return len(m) == 0
}

// loadTransaction fetches a single transaction row by ID.
func (h *BillingHandler) loadTransaction(ctx context.Context, id int64) (txnRow, error) {
	var rows []txnRow
	q := url.Values{}
	q.Set("select", "id,email,amount,currency,provider,data,metadata,expire_at")
	q.Set("id", "eq."+strconv.FormatInt(id, 10))
	q.Set("limit", "1")
	if err := h.pr.SelectService(ctx, "transactions", q, &rows); err != nil {
		return txnRow{}, err
	}
	if len(rows) == 0 {
		return txnRow{}, fmt.Errorf("transaction %d not found", id)
	}
	return rows[0], nil
}

// returnURLForMetadata builds a return URL from transaction metadata (e.g. a frontend callback URL).
func returnURLForMetadata(raw json.RawMessage) string {
	const base = "https://thinkmay.net"
	if len(raw) == 0 {
		return base
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return base
	}
	vals := url.Values{}
	for k, v := range m {
		vals.Set(k, fmt.Sprint(v))
	}
	q := vals.Encode()
	if q == "" {
		return base
	}
	return base + "?" + q
}

// fillCheckout converts the amount, calls the provider, and returns the Charge.
func (h *BillingHandler) fillCheckout(ctx context.Context, txn txnRow, rate float64) (payment.Charge, error) {
	if h.registry == nil {
		return payment.Charge{}, fmt.Errorf("payment registry not configured")
	}
	client, ok := h.registry.Get(txn.Provider)
	if !ok {
		return payment.Charge{}, fmt.Errorf("unsupported provider %q", txn.Provider)
	}
	money := payment.ToMoney(txn.Amount, txn.Currency, rate)
	return client.Charge(ctx, payment.ChargeParams{
		IdempotencyKey: strconv.FormatInt(txn.ID, 10),
		Money:          money,
		Description:    txn.Email,
		ReturnURL:      returnURLForMetadata(txn.Metadata),
	})
}

// fillCheckoutCard is like fillCheckout but charges a saved card off-session.
// token is the provider payment-method handle (pm_ref) and customerRef is the
// provider customer id (customer_ref). Both are required for off-session charges.
func (h *BillingHandler) fillCheckoutCard(ctx context.Context, txn txnRow, rate float64, token, customerRef string) (payment.Charge, error) {
	if h.registry == nil {
		return payment.Charge{}, fmt.Errorf("payment registry not configured")
	}
	client, ok := h.registry.Get(txn.Provider)
	if !ok {
		return payment.Charge{}, fmt.Errorf("unsupported provider %q", txn.Provider)
	}
	money := payment.ToMoney(txn.Amount, txn.Currency, rate)
	return client.Charge(ctx, payment.ChargeParams{
		IdempotencyKey: strconv.FormatInt(txn.ID, 10),
		Money:          money,
		Description:    txn.Email,
		Token:          token,
		CustomerRef:    customerRef,
	})
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
		{http.MethodGet, "/v1/billing/payment-methods", h.PaymentMethods},
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

// pmRow mirrors the billing.payment_methods columns returned to the client.
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

// PaymentMethods lists the saved payment methods for the authenticated user.
// GET /v1/billing/payment-methods
// Requires live DB — flagged for integration verification.
func (h *BillingHandler) PaymentMethods(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
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
		writeBillingErr(w, err)
		return
	}
	if len(users) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	userID := users[0].ID

	var rows []pmRow
	q := url.Values{}
	q.Set("select", "id,provider,customer_ref,pm_ref,brand,last4,exp_month,exp_year,is_default")
	q.Set("user_id", "eq."+strconv.FormatInt(userID, 10))
	if err := h.pr.SelectService(ctx, "payment_methods", q, &rows); err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

// resolveUserID looks up the caller's numeric user id from the "users" view by email.
// It returns an error (and writes the response) when the user is not found.
func (h *BillingHandler) resolveUserID(ctx context.Context, email string) (int64, error) {
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

func (h *BillingHandler) CreateDeposit(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	var body struct {
		Amount          float64        `json:"amount"`
		Currency        string         `json:"currency"`
		Provider        string         `json:"provider"`
		Metadata        map[string]any `json:"metadata"`
		DiscountCode    string         `json:"discount_code"`
		PaymentMethodID int64          `json:"payment_method_id"`
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

	// Call the RPC to create the deposit rows.
	var rpcResult json.RawMessage
	if err := h.pr.RPC(ctx, "create_pocket_deposit_v4", map[string]any{
		"email":         email,
		"amount":        body.Amount,
		"currency":      body.Currency,
		"provider":      body.Provider,
		"metadata":      body.Metadata,
		"discount_code": body.DiscountCode,
	}, &rpcResult); err != nil {
		writeBillingErr(w, err)
		return
	}

	// Parse the returned rows — each has {id, data}.
	// For rows with empty data, fill checkout synchronously via the registry.
	var rows []struct {
		ID   int64           `json:"id"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rpcResult, &rows); err != nil {
		// If the result is not an array (e.g. plain scalar), return as-is.
		writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rpcResult})
		return
	}

	if h.registry != nil {
		// When payment_method_id is set, look up the saved card once for the whole loop.
		// SECURITY: scope the lookup to the caller's user_id (IDOR guard) and assert
		// the card's provider matches the requested provider.
		var cardPmRef, cardCustomerRef string
		if body.PaymentMethodID > 0 {
			// Resolve caller identity to a numeric user_id first.
			callerID, err := h.resolveUserID(ctx, email)
			if err != nil {
				writeBillingErr(w, err)
				return
			}

			var pmRows []pmRow
			pmq := url.Values{}
			pmq.Set("select", "id,provider,customer_ref,pm_ref,brand,last4,exp_month,exp_year,is_default")
			pmq.Set("id", "eq."+strconv.FormatInt(body.PaymentMethodID, 10))
			pmq.Set("user_id", "eq."+strconv.FormatInt(callerID, 10))
			pmq.Set("limit", "1")
			if err := h.pr.SelectService(ctx, "payment_methods", pmq, &pmRows); err != nil {
				writeBillingErr(w, err)
				return
			}
			if len(pmRows) == 0 {
				// Card not found OR belongs to a different user — do not leak which.
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "payment_method not found"})
				return
			}
			// Assert the card's provider matches the deposit's requested provider.
			if strings.ToLower(pmRows[0].Provider) != strings.ToLower(body.Provider) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payment_method provider mismatch"})
				return
			}
			cardPmRef = pmRows[0].PmRef
			cardCustomerRef = pmRows[0].CustomerRef
		}

		for i := range rows {
			if !dataIsEmpty(rows[i].Data) {
				continue
			}
			// Load the full transaction to get all fields needed for checkout.
			txn, loadErr := h.loadTransaction(ctx, rows[i].ID)
			if loadErr != nil {
				writeBillingErr(w, loadErr)
				return
			}

			rate := 0.0
			if h.rates != nil {
				var rateErr error
				rate, rateErr = h.rates.Load(ctx, txn.Currency)
				if rateErr != nil {
					writeBillingErr(w, rateErr)
					return
				}
			}

			var ch payment.Charge
			var chErr error
			if cardPmRef != "" {
				ch, chErr = h.fillCheckoutCard(ctx, txn, rate, cardPmRef, cardCustomerRef)
			} else {
				ch, chErr = h.fillCheckout(ctx, txn, rate)
			}
			if chErr != nil {
				writeBillingErr(w, chErr)
				return
			}

			// Build stored data generically; include redirect_url for requires_action/3DS flows.
			out := map[string]any{"charge_id": ch.ID, "status": string(ch.Status)}
			if ch.RedirectURL != "" {
				out["redirect_url"] = ch.RedirectURL
			}
			if len(ch.Detail) > 0 {
				out["detail"] = ch.Detail
			}
			dataBytes, err := json.Marshal(out)
			if err != nil {
				writeBillingErr(w, err)
				return
			}
			q := url.Values{}
			q.Set("id", "eq."+strconv.FormatInt(rows[i].ID, 10))
			if err := h.pr.Update(ctx, "transactions", q, map[string]any{"data": json.RawMessage(dataBytes)}, nil); err != nil {
				writeBillingErr(w, err)
				return
			}
			rows[i].Data = dataBytes
		}
	}

	enriched, err := json.Marshal(rows)
	if err != nil {
		writeBillingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": enriched})
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
		"email":          email,
		"plan_name":      body.PlanName,
		"cluster_domain": body.ClusterDomain,
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
