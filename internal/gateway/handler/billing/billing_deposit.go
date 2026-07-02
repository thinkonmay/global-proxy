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

// txnRow mirrors the requests table columns used by billing.
type txnRow struct {
	ID          int64           `json:"id"`
	UserEmail   string          `json:"user_email"`
	PlanID      string          `json:"plan_id"`
	Currency    string          `json:"currency"`
	AmountMinor float64         `json:"amount_minor"`
	Provider    string          `json:"provider"`
	Data        json.RawMessage `json:"data"`
	Status      string          `json:"status"`
	ExpireAt    string          `json:"expire_at"`
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

// fillCheckout converts the amount, calls the provider, and returns the Charge.
// redirectMeta is the raw metadata JSON used to resolve return/cancel URLs
// (from the original deposit request body since the requests table has no metadata column).
// method optionally pre-selects a provider payment channel (e.g. PayerMax "OVO"/"DANA").
func (h *Handler) fillCheckout(ctx context.Context, txn txnRow, redirectMeta json.RawMessage, method string) (payment.Charge, error) {
	if h.registry == nil {
		return payment.Charge{}, fmt.Errorf("payment registry not configured")
	}
	client, ok := h.registry.Get(txn.Provider)
	if !ok {
		return payment.Charge{}, fmt.Errorf("unsupported provider %q", txn.Provider)
	}
	// requests.amount_minor is already the fiat charge in provider minor units.
	money := payment.Money{Amount: int64(txn.AmountMinor), Currency: strings.ToUpper(txn.Currency)}
	returnURL := buildRedirectURL(redirectMeta, metaReturnURL, "transaction_id", strconv.FormatInt(txn.ID, 10))
	cancelURL := buildRedirectURL(redirectMeta, metaCancelURL, "", "")
	return client.Charge(ctx, payment.ChargeParams{
		IdempotencyKey: strconv.FormatInt(txn.ID, 10),
		Money:          money,
		Description:    txn.UserEmail,
		CustomerEmail:  txn.UserEmail,
		ReturnURL:      returnURL,
		CancelURL:      cancelURL,
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

	// create_payment_session creates (or reuses) a pending payment session and returns its
	// metadata. When reused is true and charge_data is already stored, return it directly
	// without re-calling the provider.
	type sessionRow struct {
		ID         int64           `json:"id"`
		ChargeData json.RawMessage `json:"charge_data"`
		Status     string          `json:"status"`
		Reused     bool            `json:"reused"`
	}
	sessionArgs := map[string]any{
		"p_email":         email,
		"p_plan_id":       body.PlanName,
		"p_currency":      body.Currency,
		"p_amount_minor":  amountMinor,
		"p_credit":        creditGrant,
		"p_provider":      body.Provider,
		"p_discount_code": body.DiscountCode,
	}
	// create_payment_session RETURNS TABLE -> PostgREST returns a JSON array.
	var sessionRows []sessionRow
	if err := h.pr.RPC(ctx, "create_payment_session", sessionArgs, &sessionRows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	if len(sessionRows) == 0 {
		httpx.WriteError(w, http.StatusInternalServerError, "payment session not created")
		return
	}
	sessionResult := sessionRows[0]

	// Response is a single-element array {id,data}: the client destructures [{...}] and
	// the shared gateway client unwraps any top-level {data:…} as an envelope, so a bare
	// object would be misread — an array sidesteps both.
	// If the session was reused and charge_data is already stored, return it immediately.
	if sessionResult.Reused && len(sessionResult.ChargeData) > 0 && string(sessionResult.ChargeData) != "null" {
		httpx.WriteJSON(w, http.StatusOK, []map[string]any{{
			"id":   sessionResult.ID,
			"data": sessionResult.ChargeData,
		}})
		return
	}

	// No stored charge — call the provider to open a new checkout.
	if h.registry == nil {
		httpx.WriteError(w, http.StatusInternalServerError, "payment registry not configured")
		return
	}

	txn := txnRow{
		ID:          sessionResult.ID,
		UserEmail:   email,
		Provider:    body.Provider,
		Currency:    body.Currency,
		AmountMinor: float64(amountMinor),
	}
	redirectMeta := rawJSON(body.Metadata)

	ch, chErr := h.fillCheckout(ctx, txn, redirectMeta, body.Method)
	if chErr != nil {
		httpx.WriteUpstreamErr(w, chErr)
		return
	}

	// Marshal the whole Charge struct as the canonical charge_data blob.
	chBytes, err := json.Marshal(ch)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	// Persist the provider charge details back onto the session.
	setArgs := map[string]any{
		"p_id":          sessionResult.ID,
		"p_charge_data": json.RawMessage(chBytes),
	}
	if err := h.pr.RPC(ctx, "set_session_charge", setArgs, nil); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, []map[string]any{{
		"id":   sessionResult.ID,
		"data": json.RawMessage(chBytes),
	}})
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

	// p_email scopes the lookup to the caller's own request (the RPC runs as
	// service_role, so ownership is enforced in the function, not via RLS).
	var out json.RawMessage
	if err := h.pr.RPC(ctx, "get_request_status", map[string]any{"p_id": txID, "p_email": email}, &out); err != nil {
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

	// p_email scopes the cancel to the caller's own request; the RPC raises
	// not-found on a mismatch so a user cannot cancel another user's checkout.
	var out json.RawMessage
	if err := h.pr.RPC(ctx, "cancel_request", map[string]any{"p_id": txID, "p_email": email}, &out); err != nil {
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
		PlanName  string  `json:"plan_name"`
		MachineID *int64  `json:"machine_id"` // optional: attach to existing machine
		Template  *string `json:"template"`
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

	// buy_plan atomically purchases the plan and provisions (or re-provisions) the machine.
	// It replaces the old create_or_replace_payment + verify_all_payment_v2 pair.
	buyArgs := map[string]any{
		"p_email":   email,
		"p_plan_id": body.PlanName,
	}
	if body.MachineID != nil {
		buyArgs["p_machine_id"] = *body.MachineID
	} else {
		buyArgs["p_machine_id"] = nil
	}
	if body.Template != nil {
		buyArgs["p_template"] = *body.Template
	}
	var machineID int64
	if err := h.pr.RPC(ctx, "buy_plan", buyArgs, &machineID); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	// Sweep per-machine addon charges for all of the user's machines.
	// getMachines returns the current machine list after buy_plan has run.
	machines, err := h.getMachines(ctx, email)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	for _, m := range machines {
		if err := h.pr.RPC(ctx, "pay_addon_charges", map[string]any{
			"p_email":      email,
			"p_machine_id": m.ID,
		}, nil); err != nil {
			httpx.WriteUpstreamErr(w, err)
			return
		}
	}

	httpx.WriteData(w, true)
}

// BuyHours refills an active machine's hour quota from an hours_pack, paid from the
// user's wallet credit. It does not extend the day window. Returns the machine's new
// usage_limit. Errors (insufficient funds, non-active machine) surface from buy_hours.
func (h *Handler) BuyHours(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	var body struct {
		MachineID int64  `json:"machine_id"`
		PackID    string `json:"pack_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.MachineID == 0 || body.PackID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "machine_id and pack_id required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), billingDepositTimeout)
	defer cancel()

	var newLimit int64
	if err := h.pr.RPC(ctx, "buy_hours", map[string]any{
		"p_email":      email,
		"p_machine_id": body.MachineID,
		"p_pack_id":    body.PackID,
	}, &newLimit); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, newLimit)
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
		"p_code":      code,
		"p_apply_for": body.ApplyForType,
		"p_email":     email,
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
// get_wallet_balance returns a bigint scalar.
func (h *Handler) walletBalance(ctx context.Context, email string) (int64, error) {
	var balance int64
	if err := h.pr.RPC(ctx, "get_wallet_balance", map[string]any{"p_email": email}, &balance); err != nil {
		return 0, err
	}
	return balance, nil
}

// addonChargeTotal returns the sum of pending addon charges across all of the user's
// machines, in CREDIT. Calls get_machines then list_addon_charges per machine.
func (h *Handler) addonChargeTotal(ctx context.Context, email string) (int64, error) {
	machines, err := h.getMachines(ctx, email)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, m := range machines {
		var charges []struct {
			TotalAmount int64 `json:"total_amount"`
		}
		if err := h.pr.RPC(ctx, "list_addon_charges", map[string]any{
			"p_email":      email,
			"p_machine_id": m.ID,
		}, &charges); err != nil {
			return 0, err
		}
		for _, c := range charges {
			total += c.TotalAmount
		}
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
