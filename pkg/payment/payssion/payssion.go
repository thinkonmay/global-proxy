package payssion

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

	// Amount is already in the provider's whole-unit amount; use as-is like legacy.
	amt := args.Money.Amount
	currency := strings.ToUpper(args.Money.Currency)
	orderID := args.IdempotencyKey
	desc := payssionDescription(args.Description, amt)

	// md5 signature over api_key|pm_id|amount|currency|order_id|secret_key.
	sigRaw := c.cfg.APIKey + "|" + c.cfg.PMID + "|" + strconv.FormatInt(amt, 10) + "|" +
		currency + "|" + orderID + "|" + c.cfg.SecretKey
	sig := fmt.Sprintf("%x", md5.Sum([]byte(sigRaw)))

	form := url.Values{}
	form.Set("api_key", c.cfg.APIKey)
	form.Set("api_sig", sig)
	form.Set("pm_id", c.cfg.PMID)
	form.Set("amount", strconv.FormatInt(amt, 10))
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

// GetCharge is unsupported; legacy never polled Payssion.
func (c *Client) GetCharge(ctx context.Context, id string) (payment.Charge, error) {
	return payment.Charge{}, payment.ErrNotSupported
}

// RegisterRoutes is a no-op; Payssion delivers no webhooks here.
func (c *Client) RegisterRoutes(mux *http.ServeMux, deliver func(ctx context.Context, e payment.Event) error) {
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
func payssionDescription(desc string, amount int64) string {
	prefix := desc
	if i := strings.Index(prefix, "@"); i >= 0 {
		prefix = prefix[:i]
	}
	if len(prefix) > 15 {
		prefix = prefix[:15]
	}
	return prefix + strconv.FormatInt(amount, 10)
}
