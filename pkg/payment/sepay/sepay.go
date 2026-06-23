package sepay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/payment"
)

// Compile-time assertion that Client satisfies the payment.Client interface.
var _ payment.Client = (*Client)(nil)

const (
	sandboxCheckoutURL = "https://pay-sandbox.sepay.vn/v1/checkout/init"
	prodCheckoutURL    = "https://pay.sepay.vn/v1/checkout/init"

	proxyCheckoutPath = "/api/v1/payment/checkout/sepay"
	webhookPath       = "/api/v1/payment/webhook/sepay"
)

// Config holds the SePay provider credentials and endpoints.
type Config struct {
	MerchantID    string
	SecretKey     string
	IPNSecretKey  string
	PublicBaseURL string
	ReturnURL     string
	Sandbox       bool
}

// Client is the net/http SePay payment provider implementation.
type Client struct {
	cfg         Config
	checkoutURL string
}

// New builds a SePay client, selecting the sandbox or production checkout URL.
func New(cfg Config) payment.Client {
	checkoutURL := prodCheckoutURL
	if cfg.Sandbox {
		checkoutURL = sandboxCheckoutURL
	}
	return &Client{cfg: cfg, checkoutURL: checkoutURL}
}

// keyValue is an ordered key/value pair used to build the signature input.
type keyValue struct {
	key   string
	value string
}

// signFields computes the SePay checkout signature over the ordered fields.
// It builds the string "k1=v1,k2=v2,..." (pairs joined by ",", in the given
// order) and returns the hex-encoded HMAC-SHA256 using the merchant secret.
// NOTE: the exact algorithm (string layout, separators, hashing) must be
// verified against the SePay PHP SDK (signCheckoutFields); this is a
// best-effort port and may need adjustment.
func signFields(fields []keyValue, secret string) string {
	parts := make([]string, 0, len(fields))
	for _, kv := range fields {
		parts = append(parts, kv.key+"="+kv.value)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(mac.Sum(nil))
}

// secretEqual performs a constant-time comparison of two secret strings
// to avoid timing-based attacks. Returns true if the secrets are equal.
func secretEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// addRef appends the transaction ref to a URL as the "ref" query param,
// preserving any existing query string.
func addRef(rawURL, ref string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fall back to a naive append if the URL cannot be parsed.
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		return rawURL + sep + "ref=" + url.QueryEscape(ref)
	}
	q := u.Query()
	q.Set("ref", ref)
	u.RawQuery = q.Encode()
	return u.String()
}

// checkoutFieldOrder is the canonical field order required for SePay's signature.
// Mirror SePay PHP SDK's CheckoutResource::prepareFormFields insertion order
// (excludes `signature`, which is appended last as a separate form input).
var checkoutFieldOrder = []string{
	"merchant",
	"currency",
	"order_amount",
	"operation",
	"order_description",
	"payment_method",
	"order_invoice_number",
	"customer_id",
	"success_url",
	"error_url",
	"cancel_url",
}

const (
	notifTypeOrderPaid       = "ORDER_PAID"
	notifTypeTransactionVoid = "TRANSACTION_VOID"
)

// ipnPayload is the SePay IPN webhook JSON body.
type ipnPayload struct {
	NotificationType string `json:"notification_type"`
	Order            struct {
		OrderStatus        string `json:"order_status"`
		OrderInvoiceNumber string `json:"order_invoice_number"`
		OrderAmount        string `json:"order_amount"`
	} `json:"order"`
	Transaction struct {
		TransactionID     string `json:"transaction_id"`
		TransactionStatus string `json:"transaction_status"`
	} `json:"transaction"`
}

// Name identifies the provider for registry lookup.
func (c *Client) Name() string { return "sepay" }

// Charge builds a signed SePay checkout and returns the proxy checkout redirect URL.
func (c *Client) Charge(ctx context.Context, args payment.ChargeParams) (payment.Charge, error) {
	invoiceNumber := args.IdempotencyKey

	returnURL := args.ReturnURL
	if returnURL == "" {
		returnURL = c.cfg.ReturnURL
	}

	// Field order matches SePay PHP SDK's signCheckoutFields allowlist iteration:
	// merchant, currency, order_amount, operation, order_description,
	// payment_method, order_invoice_number, customer_id,
	// success_url, error_url, cancel_url.
	// HMAC input is "k1=v1,k2=v2,..." in this exact order.
	fields := []keyValue{
		{"merchant", c.cfg.MerchantID},
		{"currency", "VND"}, // SePay is VND-only.
		{"order_amount", fmt.Sprintf("%d", args.Money.Amount)},
		{"operation", "PURCHASE"},
		{"order_description", args.Description},
		{"payment_method", "BANK_TRANSFER"},
		{"order_invoice_number", invoiceNumber},
	}
	if returnURL != "" {
		// All three redirect URLs carry only the transaction ref. The FE
		// fetches the transaction row and derives outcome from its status.
		fields = append(fields,
			keyValue{"success_url", addRef(returnURL, invoiceNumber)},
			keyValue{"error_url", addRef(returnURL, invoiceNumber)},
			keyValue{"cancel_url", addRef(returnURL, invoiceNumber)},
		)
	}

	sig := signFields(fields, c.cfg.SecretKey)

	q := url.Values{}
	for _, kv := range fields {
		q.Set(kv.key, kv.value)
	}
	q.Set("signature", sig)

	redirectURL := strings.TrimRight(c.cfg.PublicBaseURL, "/") + proxyCheckoutPath + "?" + q.Encode()

	return payment.Charge{
		ID:          invoiceNumber,
		Status:      payment.StatusPending,
		RedirectURL: redirectURL,
	}, nil
}

// GetCharge is unsupported: SePay is webhook-driven with no status query API.
func (c *Client) GetCharge(ctx context.Context, id string) (payment.Charge, error) {
	return payment.Charge{}, payment.ErrNotSupported
}

// Refund is unsupported by the SePay provider.
func (c *Client) Refund(ctx context.Context, args payment.RefundParams) (payment.Refund, error) {
	return payment.Refund{}, payment.ErrNotSupported
}

// RegisterRoutes wires the proxy checkout form and the IPN webhook into the mux.
func (c *Client) RegisterRoutes(mux *http.ServeMux, deliver func(ctx context.Context, e payment.Event) error) {
	// SePay /v1/checkout/init is POST-only and expects a browser-submitted form
	// (session cookies + IP fingerprint tied to the user's browser). This route
	// renders an auto-submitting HTML form so navigation lands the user on
	// SePay's domain with their own session.
	//
	// SePay verifies the signature against the POST body in submission order, so
	// the form's input element order MUST match the canonical sign order; map
	// iteration is non-deterministic and breaks signature verification.
	mux.HandleFunc(proxyCheckoutPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		if len(q) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var buf strings.Builder
		buf.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Redirecting to SePay…</title></head><body><form id="sp" method="POST" action="`)
		buf.WriteString(html.EscapeString(c.checkoutURL))
		buf.WriteString(`">`)
		for _, name := range checkoutFieldOrder {
			v := q.Get(name)
			if v == "" {
				continue
			}
			buf.WriteString(`<input type="hidden" name="`)
			buf.WriteString(html.EscapeString(name))
			buf.WriteString(`" value="`)
			buf.WriteString(html.EscapeString(v))
			buf.WriteString(`">`)
		}
		if sig := q.Get("signature"); sig != "" {
			buf.WriteString(`<input type="hidden" name="signature" value="`)
			buf.WriteString(html.EscapeString(sig))
			buf.WriteString(`">`)
		}
		buf.WriteString(`<noscript><button type="submit">Continue to SePay</button></noscript></form><script>document.getElementById('sp').submit();</script></body></html>`)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(buf.String()))
	})

	mux.HandleFunc(webhookPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !secretEqual(r.Header.Get("X-Secret-Key"), c.cfg.IPNSecretKey) {
			slog.Error("sepay webhook: invalid secret key")
			writeJSON(w, http.StatusUnauthorized, map[string]bool{"success": false})
			return
		}

		var payload ipnPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			slog.Error("sepay webhook: decode body", slog.Any("error", err))
			writeJSON(w, http.StatusBadRequest, map[string]bool{"success": false})
			return
		}

		invoiceNumber := payload.Order.OrderInvoiceNumber
		if invoiceNumber == "" {
			slog.Error("sepay webhook: missing order_invoice_number")
			writeJSON(w, http.StatusBadRequest, map[string]bool{"success": false})
			return
		}

		status, ok := mapNotificationType(payload.NotificationType)
		if !ok {
			// Unknown notification type: acknowledge so SePay stops retrying.
			slog.Warn("sepay webhook: unknown notification_type",
				slog.String("notification_type", payload.NotificationType),
				slog.String("invoice", invoiceNumber))
			writeJSON(w, http.StatusOK, map[string]bool{"success": true})
			return
		}

		event := payment.Event{
			Kind:   payment.EventCharge,
			ID:     invoiceNumber,
			Status: status,
		}

		if err := deliver(r.Context(), event); err != nil {
			slog.Error("sepay webhook: deliver error", slog.Any("error", err))
		}

		writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// mapNotificationType maps a SePay notification type to a normalized status.
func mapNotificationType(t string) (payment.Status, bool) {
	switch t {
	case notifTypeOrderPaid:
		return payment.StatusSuccess, true
	case notifTypeTransactionVoid:
		return payment.StatusFailed, true
	default:
		return "", false
	}
}
