package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

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
func (h *Handler) loadTransaction(ctx context.Context, id int64) (txnRow, error) {
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

// Metadata keys consumed as redirect targets — never echoed back as query params.
const (
	metaReturnURL = "return_url"
	metaCancelURL = "cancel_url"
)

// buildRedirectURL builds a provider redirect URL from transaction metadata.
//
// The frontend may pass an absolute URL under baseKey ("return_url" /
// "cancel_url") — used as the base, path preserved — otherwise a default base is
// used. When idKey is set, idVal is appended under that key so the landing page
// can verify settlement; this matters for Stripe hosted checkout, where the
// full-page redirect loses SPA state. Remaining metadata keys are appended as
// query params (legacy PayerMax callback behavior); the reserved redirect keys
// are stripped so they never leak into the query.
func buildRedirectURL(raw json.RawMessage, baseKey, idKey, idVal string) string {
	base := "https://thinkmay.net"
	m := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	if v, ok := m[baseKey].(string); ok {
		if strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://") {
			base = v
		}
	}
	delete(m, metaReturnURL)
	delete(m, metaCancelURL)
	vals := url.Values{}
	for k, v := range m {
		vals.Set(k, fmt.Sprint(v))
	}
	if idKey != "" {
		vals.Set(idKey, idVal)
	}
	enc := vals.Encode()
	if enc == "" {
		return base
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + enc
}

// returnURLForTxn builds the deposit success URL, tagging it with the txn id.
func returnURLForTxn(txn txnRow) string {
	return buildRedirectURL(txn.Metadata, metaReturnURL, "transaction_id", strconv.FormatInt(txn.ID, 10))
}

// cancelURLForTxn builds the deposit cancel URL. No txn id is appended — a
// cancelled checkout has nothing to verify; the user just returns to the picker.
func cancelURLForTxn(txn txnRow) string {
	return buildRedirectURL(txn.Metadata, metaCancelURL, "", "")
}

// fillCheckout converts the amount, calls the provider, and returns the Charge.
// method optionally pre-selects a provider payment channel (e.g. PayerMax "OVO"/"DANA").
func (h *Handler) fillCheckout(ctx context.Context, txn txnRow, method string) (payment.Charge, error) {
	if h.registry == nil {
		return payment.Charge{}, fmt.Errorf("payment registry not configured")
	}
	client, ok := h.registry.Get(txn.Provider)
	if !ok {
		return payment.Charge{}, fmt.Errorf("unsupported provider %q", txn.Provider)
	}
	// transactions.amount_minor is already the fiat charge in provider minor units.
	money := payment.Money{Amount: int64(txn.Amount), Currency: strings.ToUpper(txn.Currency)}
	return client.Charge(ctx, payment.ChargeParams{
		IdempotencyKey: strconv.FormatInt(txn.ID, 10),
		Money:          money,
		Description:    txn.Email,
		ReturnURL:      returnURLForTxn(txn),
		CancelURL:      cancelURLForTxn(txn),
		Method:         method,
	})
}

func (h *Handler) CreateDeposit(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	var body struct {
		Amount       float64        `json:"amount"`
		Currency     string         `json:"currency"`
		Provider     string         `json:"provider"`
		Metadata     map[string]any `json:"metadata"`
		DiscountCode string         `json:"discount_code"`
		Method       string         `json:"method"` // optional provider channel (e.g. "OVO"/"DANA")
		Credit       *int64         `json:"credit"` // fixed CREDIT to grant (plan purchase); nil = legacy amount*rate top-up
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Amount <= 0 || body.Currency == "" || body.Provider == "" {
		httpx.WriteError(w, http.StatusBadRequest, "amount, currency, and provider required")
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
	// Website/catalog amounts are MAJOR units; convert to provider minor once here
	// (single boundary) so transactions.amount_minor stays canonical minor everywhere.
	amountMinor := payment.FromMajor(body.Amount, body.Currency).Minor()
	depositArgs := map[string]any{
		"email":         email,
		"amount":        amountMinor,
		"currency":      body.Currency,
		"provider":      body.Provider,
		"metadata":      body.Metadata,
		"discount_code": body.DiscountCode,
	}
	if body.Credit != nil {
		depositArgs["credit_grant"] = *body.Credit
	}
	var rpcResult json.RawMessage
	if err := h.pr.RPC(ctx, "create_pocket_deposit_v4", depositArgs, &rpcResult); err != nil {
		httpx.WriteUpstreamErr(w, err)
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
		httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rpcResult})
		return
	}

	if h.registry != nil {
		for i := range rows {
			if !dataIsEmpty(rows[i].Data) {
				continue
			}
			// Load the full transaction to get all fields needed for checkout.
			txn, loadErr := h.loadTransaction(ctx, rows[i].ID)
			if loadErr != nil {
				httpx.WriteUpstreamErr(w, loadErr)
				return
			}

			ch, chErr := h.fillCheckout(ctx, txn, body.Method)
			if chErr != nil {
				httpx.WriteUpstreamErr(w, chErr)
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
				httpx.WriteUpstreamErr(w, err)
				return
			}
			q := url.Values{}
			q.Set("id", "eq."+strconv.FormatInt(rows[i].ID, 10))
			if err := h.pr.Update(ctx, "transactions", q, map[string]any{"data": json.RawMessage(dataBytes)}, nil); err != nil {
				httpx.WriteUpstreamErr(w, err)
				return
			}
			rows[i].Data = dataBytes
		}
	}

	enriched, err := json.Marshal(rows)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": enriched})
}

func (h *Handler) DepositStatus(w http.ResponseWriter, r *http.Request) {
	_, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	txID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("transactionId")), 10, 64)
	if err != nil || txID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid transaction id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "get_transaction_status", map[string]any{"id": txID}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": out})
}

func (h *Handler) CancelDeposit(w http.ResponseWriter, r *http.Request) {
	_, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	txID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("transactionId")), 10, 64)
	if err != nil || txID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid transaction id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "cancel_transaction", map[string]any{"id": txID}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}

func (h *Handler) CreatePayment(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	var body struct {
		PlanName      string  `json:"plan_name"`
		ClusterDomain string  `json:"cluster_domain"`
		Template      *string `json:"template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.PlanName == "" || body.ClusterDomain == "" {
		httpx.WriteError(w, http.StatusBadRequest, "plan_name and cluster_domain required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), billingDepositTimeout)
	defer cancel()

	var discard json.RawMessage
	if err := h.pr.RPC(ctx, "pay_all_addon_charges", map[string]any{"email": email}, &discard); err != nil {
		httpx.WriteUpstreamErr(w, err)
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
		httpx.WriteUpstreamErr(w, err)
		return
	}
	if err := h.pr.RPC(ctx, "verify_all_payment_v2", map[string]any{}, &discard); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, true)
}

func (h *Handler) ValidateDiscount(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	var body struct {
		Code         string `json:"code"`
		DiscountCode string `json:"discount_code"`
		ApplyForType string `json:"apply_for_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		code = strings.TrimSpace(body.DiscountCode)
	}
	if code == "" || body.ApplyForType == "" {
		httpx.WriteError(w, http.StatusBadRequest, "code and apply_for_type required")
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
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}
