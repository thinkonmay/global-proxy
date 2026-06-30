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
		CustomerEmail:  txn.Email,
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
		PlanName        string         `json:"plan_name"`
		Provider        string         `json:"provider"`
		Currency        string         `json:"currency"`
		PocketDeduction bool           `json:"pocket_deduction"` // apply existing wallet balance toward the cost
		DiscountCode    string         `json:"discount_code"`
		Method          string         `json:"method"`   // optional provider channel (e.g. "OVO"/"DANA")
		Metadata        map[string]any `json:"metadata"` // return_url/cancel_url etc. (carries plan_name for the success page)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.PlanName == "" || body.Currency == "" || body.Provider == "" {
		httpx.WriteError(w, http.StatusBadRequest, "plan_name, currency, and provider required")
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

	// The client sends ONLY the plan it wants — never an amount or credit, both of which a
	// tampered client could lower to underpay. The fiat charge AND the granted CREDIT are
	// computed SERVER-SIDE from the plan catalog, the user's wallet balance, and pending
	// addon charges (mirrors the website IdentifyAmount): the wallet covers the cost first,
	// the deposit funds only the shortfall. Discounts reduce the fiat inside the RPC.
	planCredit, priceMajor, err := h.planCatalog(ctx, body.PlanName, body.Currency)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	rate, err := h.rates.Load(ctx, body.Currency)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	balance, err := h.walletBalance(ctx, email)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	addonCredit, err := h.addonChargeTotal(ctx, email)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	chargeMajor, creditGrant := computePlanDeposit(planDepositInput{
		PlanCredit:   planCredit,
		PriceMajor:   priceMajor,
		AddonCredit:  addonCredit,
		Balance:      balance,
		Rate:         rate,
		PocketDeduct: body.PocketDeduction,
	})
	if creditGrant <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "wallet balance already covers this plan; no deposit required")
		return
	}
	amountMinor := payment.FromMajor(chargeMajor, body.Currency).Minor()

	// A deposit only tops up the wallet (create_pocket_deposit_v4); buying the plan from the
	// topped-up balance is a separate step (POST /v1/billing/payments → create_or_replace_payment).
	var rpcResult json.RawMessage
	depositArgs := map[string]any{
		"email":         email,
		"amount":        amountMinor,
		"currency":      body.Currency,
		"provider":      body.Provider,
		"metadata":      body.Metadata,
		"discount_code": body.DiscountCode,
		"credit_grant":  creditGrant,
	}
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
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
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

	// p_email scopes the lookup to the caller's own transaction (the RPC runs as
	// service_role, so ownership is enforced in the function, not via RLS).
	var out json.RawMessage
	if err := h.pr.RPC(ctx, "get_transaction_status", map[string]any{"id": txID, "p_email": email}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": out})
}

func (h *Handler) CancelDeposit(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
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

	// p_email scopes the cancel to the caller's own transaction; the RPC raises
	// not-found on a mismatch so a user cannot cancel another user's checkout.
	var out json.RawMessage
	if err := h.pr.RPC(ctx, "cancel_transaction", map[string]any{"id": txID, "p_email": email}, &out); err != nil {
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
	if body.PlanName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "plan_name required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), billingDepositTimeout)
	defer cancel()

	clusterDomain, err := h.resolveClusterDomain(ctx, body.ClusterDomain)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	// These RPCs return void; PostgREST replies with an empty body, so pass nil
	// dest to skip decoding (decoding empty into json.RawMessage fails).
	if err := h.pr.RPC(ctx, "pay_all_addon_charges", map[string]any{"email": email}, nil); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	args := map[string]any{
		"email":          email,
		"plan_name":      body.PlanName,
		"cluster_domain": clusterDomain,
	}
	if body.Template != nil {
		args["template"] = *body.Template
	}
	if err := h.pr.RPC(ctx, "create_or_replace_payment", args, nil); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	if err := h.pr.RPC(ctx, "verify_all_payment_v2", map[string]any{}, nil); err != nil {
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

// planCatalog returns the plan's CREDIT and its MAJOR-unit fiat price for the currency,
// read from the authoritative billing.plans catalog. Errors if the plan is missing,
// inactive, or has no price for the currency.
func (h *Handler) planCatalog(ctx context.Context, planName, currency string) (int64, float64, error) {
	currency = strings.ToUpper(strings.TrimSpace(currency))
	q := url.Values{}
	q.Set("select", "credit,price->"+currency)
	q.Set("active", "eq.true")
	q.Set("name", "eq."+planName)
	q.Set("limit", "1")
	var rows []map[string]json.RawMessage
	if err := h.pr.SelectService(ctx, "plans", q, &rows); err != nil {
		return 0, 0, err
	}
	if len(rows) == 0 {
		return 0, 0, fmt.Errorf("plan %q not found or inactive", planName)
	}
	var credit int64
	if raw, ok := rows[0]["credit"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &credit); err != nil {
			return 0, 0, fmt.Errorf("plan %q malformed credit: %w", planName, err)
		}
	}
	priceRaw, ok := rows[0][currency]
	if !ok || len(priceRaw) == 0 || string(priceRaw) == "null" {
		return 0, 0, fmt.Errorf("plan %q has no %s price", planName, currency)
	}
	var priceMajor float64
	if err := json.Unmarshal(priceRaw, &priceMajor); err != nil {
		return 0, 0, fmt.Errorf("plan %q malformed %s price: %w", planName, currency, err)
	}
	if credit <= 0 || priceMajor <= 0 {
		return 0, 0, fmt.Errorf("plan %q has non-positive credit or price", planName)
	}
	return credit, priceMajor, nil
}

// walletBalance returns the caller's current CREDIT balance (0 if no wallet yet).
func (h *Handler) walletBalance(ctx context.Context, email string) (int64, error) {
	var rows []struct {
		Amount int64 `json:"amount"`
	}
	if err := h.pr.RPC(ctx, "get_pocket_balance", map[string]any{"email": email}, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Amount, nil
}

// addonChargeTotal returns the sum of the caller's pending addon charges, in CREDIT.
func (h *Handler) addonChargeTotal(ctx context.Context, email string) (int64, error) {
	var rows []struct {
		TotalAmount int64 `json:"total_amount"`
	}
	if err := h.pr.RPC(ctx, "list_addon_charges_v2", map[string]any{"input_email": email}, &rows); err != nil {
		return 0, err
	}
	var total int64
	for _, r := range rows {
		total += r.TotalAmount
	}
	return total, nil
}

// planDepositInput is the catalog + account state needed to size a plan-purchase deposit.
type planDepositInput struct {
	PlanCredit   int64   // plans.credit (CREDIT the plan costs)
	PriceMajor   float64 // plans.price[currency], MAJOR fiat units
	AddonCredit  int64   // pending addon charges, CREDIT
	Balance      int64   // wallet balance, CREDIT
	Rate         float64 // currency_rates.rate_to_system_credit (CREDIT per MAJOR fiat unit)
	PocketDeduct bool    // apply existing balance toward the cost
}

// computePlanDeposit mirrors the website IdentifyAmount: the wallet balance covers the
// plan first then addons, and the deposit funds only the remaining shortfall. It returns
// the fiat to charge (MAJOR units) and the CREDIT the deposit must mint. The plan portion
// is priced from the catalog fiat price (price * shortfall/credit); the addon portion is
// converted from CREDIT at the FX rate. Pure function — no I/O — so it is unit-tested.
func computePlanDeposit(in planDepositInput) (chargeMajor float64, creditGrant int64) {
	planCov := int64(0)
	if in.PocketDeduct {
		planCov = minInt64(in.Balance, in.PlanCredit)
	}
	planShort := in.PlanCredit - planCov
	addonCov := int64(0)
	if in.PocketDeduct {
		addonCov = minInt64(in.Balance-planCov, in.AddonCredit)
	}
	addonShort := in.AddonCredit - addonCov

	var planFiat float64
	if in.PlanCredit > 0 {
		planFiat = in.PriceMajor * float64(planShort) / float64(in.PlanCredit)
	}
	var addonFiat float64
	if in.Rate > 0 {
		addonFiat = float64(addonShort) / in.Rate
	}
	return planFiat + addonFiat, planShort + addonShort
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
