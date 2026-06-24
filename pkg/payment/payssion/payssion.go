package payssion

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

var _ payment.Client = (*Client)(nil)

// Config holds Payssion credentials and the API base link (mirrors legacy payssionConfig).
type Config struct {
	APIKey    string
	PMID      string
	SecretKey string
	Link      string
}

// Client is the Payssion payment provider; it speaks raw form POST with an md5 signature (no SDK).
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a Payssion client with a 15s HTTP timeout.
func New(cfg Config) payment.Client {
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// Name identifies the provider for registry lookup.
func (c *Client) Name() string { return "payssion" }

// Charge creates a Payssion payment and returns its hosted redirect URL.
func (c *Client) Charge(ctx context.Context, args payment.ChargeParams) (payment.Charge, error) {
	if c.cfg.APIKey == "" || c.cfg.PMID == "" || c.cfg.SecretKey == "" || c.cfg.Link == "" {
		return payment.Charge{}, fmt.Errorf("payssion config incomplete")
	}

	// Payssion's "amount" is in major units. Money.Major() is the single source for
	// minor->major (currency precision lives only in payment.minorUnitExponent). The
	// exact same string is used in the signature and the form so they always agree.
	amtStr := args.Money.Major()
	currency := strings.ToUpper(args.Money.Currency)
	orderID := args.IdempotencyKey
	desc := payssionDescription(args.Description, amtStr)

	// md5 signature over api_key|pm_id|amount|currency|order_id|secret_key.
	sigRaw := c.cfg.APIKey + "|" + c.cfg.PMID + "|" + amtStr + "|" +
		currency + "|" + orderID + "|" + c.cfg.SecretKey
	sig := fmt.Sprintf("%x", md5.Sum([]byte(sigRaw)))

	form := url.Values{}
	form.Set("api_key", c.cfg.APIKey)
	form.Set("api_sig", sig)
	form.Set("pm_id", c.cfg.PMID)
	form.Set("amount", amtStr)
	form.Set("currency", currency)
	form.Set("order_id", orderID)
	form.Set("description", desc)

	link := strings.TrimRight(c.cfg.Link, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, link+"payment/create", strings.NewReader(form.Encode()))
	if err != nil {
		return payment.Charge{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	respBody, status, err := c.do(req)
	if err != nil {
		return payment.Charge{}, err
	}
	if status < 200 || status >= 300 {
		return payment.Charge{}, fmt.Errorf("payssion checkout: status %d: %s", status, respBody)
	}

	var parsed struct {
		ResultCode  int    `json:"result_code"`
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return payment.Charge{}, err
	}
	if parsed.ResultCode != 200 {
		return payment.Charge{}, fmt.Errorf("payssion checkout failed: %s", respBody)
	}

	return payment.Charge{
		ID:          args.IdempotencyKey,
		Status:      payment.StatusPending,
		RedirectURL: parsed.RedirectURL,
		Detail:      json.RawMessage(respBody),
	}, nil
}

// GetCharge queries a payment's current state — the poll fallback for the webhook.
// id is our order_id (== transaction id), the same key passed at Charge time.
//
// ⚠️ UNVERIFIED against a live account. Payssion's public docs now describe a v2
// API (GET https://api.payssion.com/v2/payments/{id}) with different auth and
// keyed by Payssion's own payment id, which we don't hold until the webhook. This
// implementation targets the v1 details endpoint and reuses THIS codebase's
// order_id-based signature convention (the same generation Charge uses). Confirm
// the endpoint path, api_sig formula, and response shape in the Payssion sandbox
// before relying on poll; until then the webhook is the authoritative settle path.
func (c *Client) GetCharge(ctx context.Context, id string) (payment.Charge, error) {
	if c.cfg.APIKey == "" || c.cfg.SecretKey == "" || c.cfg.Link == "" {
		return payment.Charge{}, fmt.Errorf("payssion config incomplete")
	}

	// v1 details signature: md5(api_key|order_id|secret_key) — consistent with
	// this codebase's create signature, which is also order_id-based.
	sigRaw := c.cfg.APIKey + "|" + id + "|" + c.cfg.SecretKey
	sig := fmt.Sprintf("%x", md5.Sum([]byte(sigRaw)))

	form := url.Values{}
	form.Set("api_key", c.cfg.APIKey)
	form.Set("api_sig", sig)
	form.Set("order_id", id)

	link := strings.TrimRight(c.cfg.Link, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, link+"payment/details", strings.NewReader(form.Encode()))
	if err != nil {
		return payment.Charge{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	respBody, status, err := c.do(req)
	if err != nil {
		return payment.Charge{}, err
	}
	if status < 200 || status >= 300 {
		return payment.Charge{}, fmt.Errorf("payssion details: status %d: %s", status, respBody)
	}

	// Response shape varies by API generation; read state from either the nested
	// transaction object or the top level. result_code 200 == success envelope.
	var parsed struct {
		ResultCode  int `json:"result_code"`
		State       string `json:"state"`
		Transaction struct {
			State         string `json:"state"`
			TransactionID string `json:"transaction_id"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return payment.Charge{}, err
	}
	if parsed.ResultCode != 0 && parsed.ResultCode != 200 {
		return payment.Charge{}, fmt.Errorf("payssion details failed: %s", respBody)
	}

	state := parsed.Transaction.State
	if state == "" {
		state = parsed.State
	}
	st, terminal := mapState(state)
	if !terminal {
		// Non-terminal/unknown → report pending so the poller skips settling.
		st = payment.StatusPending
	}
	return payment.Charge{
		ID:     id,
		Status: st,
		Detail: json.RawMessage(respBody),
	}, nil
}

// Subscribe is unsupported: Payssion has no recurring billing here.
func (c *Client) Subscribe(ctx context.Context, args payment.SubscribeParams) (payment.Subscription, error) {
	return payment.Subscription{}, payment.ErrNotSupported
}

// GetSubscription is unsupported for Payssion.
func (c *Client) GetSubscription(ctx context.Context, id string) (payment.Subscription, error) {
	return payment.Subscription{}, payment.ErrNotSupported
}

// CancelSubscription is unsupported for Payssion.
func (c *Client) CancelSubscription(ctx context.Context, id string) error {
	return payment.ErrNotSupported
}

// mapState maps a Payssion notification state to a normalized settle Status.
// terminal=false means do NOT settle (caller acks and waits):
//   - pending / paid_partial: not final yet.
//   - refunded / chargeback: post-success reversals; settle_transaction can't
//     model these (a refund needs a ledger reversal, not a status flip) — handled
//     out of band. TODO: wire refund/chargeback to a credit-reversal path.
// Payssion's documented states: completed, pending, paid_partial, failed,
// cancelled_by_user, cancelled, expired, rejected_by_bank, error, refunded, chargeback.
func mapState(state string) (payment.Status, bool) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "completed":
		return payment.StatusSuccess, true
	case "failed", "error", "rejected_by_bank":
		return payment.StatusFailed, true
	case "cancelled", "cancelled_by_user", "expired":
		return payment.StatusCanceled, true
	default: // pending, paid_partial, refunded, chargeback, unknown
		return "", false
	}
}

// RegisterRoutes mounts POST /api/v1/payment/webhook/payssion.
// Payssion delivers a server-to-server notification as a form POST whose
// authenticity is an md5 signature (Payssion's protocol, not our choice) over
//   api_key|pm_id|amount|currency|track_id|sub_track_id|state|secret_key
// Note the signature does NOT include order_id; order_id is echoed separately and
// is our transaction id, so it becomes the event RefID. On a verified terminal
// state it emits a normalized EventCharge the settle worker applies idempotently.
// Non-terminal states are acked without settling; bad signatures are rejected 400.
// Payssion expects a literal "OK" body to stop retrying.
func (c *Client) RegisterRoutes(mux *http.ServeMux, deliver func(ctx context.Context, e payment.Event) error) {
	mux.HandleFunc("POST /api/v1/payment/webhook/payssion", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "cannot parse form", http.StatusBadRequest)
			return
		}
		pmID := r.PostForm.Get("pm_id")
		amount := r.PostForm.Get("amount") // use the exact string Payssion sent; do not reformat
		currency := r.PostForm.Get("currency")
		trackID := r.PostForm.Get("track_id")         // Payssion's transaction id
		subTrackID := r.PostForm.Get("sub_track_id")  // Payssion's sub-transaction id
		orderID := r.PostForm.Get("order_id")         // our transaction id, echoed back
		state := r.PostForm.Get("state")
		gotSig := strings.ToLower(strings.TrimSpace(r.PostForm.Get("notify_sig")))

		sigRaw := c.cfg.APIKey + "|" + pmID + "|" + amount + "|" + currency + "|" +
			trackID + "|" + subTrackID + "|" + state + "|" + c.cfg.SecretKey
		wantSig := fmt.Sprintf("%x", md5.Sum([]byte(sigRaw)))
		if gotSig == "" || !hmac.Equal([]byte(gotSig), []byte(wantSig)) {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		if orderID == "" {
			http.Error(w, "missing order_id", http.StatusBadRequest)
			return
		}

		status, terminal := mapState(state)
		if !terminal {
			_, _ = w.Write([]byte("OK")) // ack; wait for a terminal notification
			return
		}
		if err := deliver(r.Context(), payment.Event{
			Kind:       payment.EventCharge,
			ProviderID: trackID,
			RefID:      orderID,
			Status:     status,
		}); err != nil {
			http.Error(w, "failed to deliver event", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("OK"))
	})
}

// do executes an HTTP request and returns the body and status code.
func (c *Client) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// payssionDescription builds a short description from the given text and amount (ports payosDescription).
func payssionDescription(desc string, amount string) string {
	prefix := desc
	if i := strings.Index(prefix, "@"); i >= 0 {
		prefix = prefix[:i]
	}
	if len(prefix) > 15 {
		prefix = prefix[:15]
	}
	return prefix + amount
}
