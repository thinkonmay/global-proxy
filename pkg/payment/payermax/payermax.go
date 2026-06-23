// Package payermax implements the payment.Client interface for the PayerMax provider.
package payermax

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	payermaxsdk "github.com/shareit-payermax/payermax-server-sdk-go/payermax"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

// Config holds PayerMax credentials and endpoint; mirrors the legacy payerMaxConfig.
type Config struct {
	AppID      string
	MerchantNo string
	BaseURL    string
	PrivateKey string
	PublicKey  string
}

// Client is a PayerMax payment provider.
type Client struct {
	cfg Config
}

var _ payment.Client = (*Client)(nil)

// New constructs a PayerMax payment client.
func New(cfg Config) payment.Client {
	return &Client{cfg: cfg}
}

// Name identifies the provider for registry lookup.
func (c *Client) Name() string { return "payermax" }

// normalizeBaseURL defaults to the SDK prod URL and ensures a trailing slash.
func normalizeBaseURL(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return payermaxsdk.Prod
	}
	return strings.TrimRight(base, "/") + "/"
}

// country maps a currency to its PayerMax country code (USD→US, else ID).
func country(currency string) string {
	if strings.EqualFold(currency, "USD") {
		return "US"
	}
	return "ID"
}

// sdkClient builds the underlying PayerMax SDK client, enforcing required config.
func (c *Client) sdkClient() (*payermaxsdk.Client, error) {
	if c.cfg.AppID == "" || c.cfg.MerchantNo == "" {
		return nil, fmt.Errorf("payermax app_id/merchant_no not configured")
	}
	if c.cfg.PrivateKey == "" {
		return nil, fmt.Errorf("payermax private_key not configured")
	}
	if c.cfg.PublicKey == "" {
		return nil, fmt.Errorf("payermax public_key not configured (required for SDK response verification)")
	}
	return payermaxsdk.CreateClient(
		c.cfg.AppID,
		c.cfg.MerchantNo,
		c.cfg.PrivateKey,
		c.cfg.PublicKey,
		"", "",
		payermaxsdk.ClientSettings{
			BaseUrl:       normalizeBaseURL(c.cfg.BaseURL),
			ClientTimeout: 15 * time.Second,
		},
	)
}

// majorAmount converts a minor-unit amount to the major-unit string PayerMax expects.
// PayerMax totalAmount is in major units. USD has 2 decimal places, so Money.Amount
// (cents) is divided by 100 and formatted with 2 decimals. IDR has no minor unit, so
// the integer minor amount is sent as-is.
func majorAmount(amount int64, currency string) string {
	if strings.EqualFold(currency, "USD") {
		return strconv.FormatFloat(float64(amount)/100, 'f', 2, 64)
	}
	return strconv.FormatInt(amount, 10)
}

// Charge initiates a hosted-checkout charge via PayerMax orderAndPay.
func (c *Client) Charge(ctx context.Context, args payment.ChargeParams) (payment.Charge, error) {
	cur := strings.ToUpper(strings.TrimSpace(args.Money.Currency))
	if cur != "USD" && cur != "IDR" {
		return payment.Charge{}, fmt.Errorf("payermax only supports USD or IDR")
	}
	client, err := c.sdkClient()
	if err != nil {
		return payment.Charge{}, err
	}

	outTradeNo := "P" + args.IdempotencyKey
	payload, err := json.Marshal(map[string]string{
		"userId":           "U10001",
		"integrate":        "Hosted_Checkout",
		"outTradeNo":       outTradeNo,
		"totalAmount":      majorAmount(args.Money.Amount, cur),
		"currency":         cur,
		"country":          country(cur),
		"subject":          "Thinkmay Service",
		"body":             "Order # " + args.IdempotencyKey,
		"frontCallbackUrl": args.ReturnURL,
	})
	if err != nil {
		return payment.Charge{}, err
	}

	resp, err := client.Send("orderAndPay", string(payload))
	if err != nil {
		return payment.Charge{}, err
	}

	redirectURL, err := parseRedirectURL([]byte(resp))
	if err != nil {
		return payment.Charge{}, err
	}

	return payment.Charge{
		ID:          outTradeNo,
		Status:      payment.StatusPending,
		RedirectURL: redirectURL,
		Detail:      json.RawMessage(resp),
	}, nil
}

// GetCharge fetches the current state of a charge; id is the PayerMax outTradeNo.
func (c *Client) GetCharge(ctx context.Context, id string) (payment.Charge, error) {
	client, err := c.sdkClient()
	if err != nil {
		return payment.Charge{}, err
	}
	payload, err := json.Marshal(map[string]string{"outTradeNo": id})
	if err != nil {
		return payment.Charge{}, err
	}
	resp, err := client.Send("orderQuery", string(payload))
	if err != nil {
		return payment.Charge{}, err
	}

	var parsed struct {
		Code string `json:"code"`
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		return payment.Charge{}, err
	}
	if parsed.Code != "APPLY_SUCCESS" {
		return payment.Charge{}, fmt.Errorf("payermax query: %s", resp)
	}

	// Map PayerMax order status to the normalized payment status.
	var status payment.Status
	switch parsed.Data.Status {
	case "SUCCESS":
		status = payment.StatusSuccess
	case "FAILED", "CLOSED":
		status = payment.StatusCanceled
	default:
		status = payment.StatusPending
	}

	return payment.Charge{ID: id, Status: status}, nil
}

// parseRedirectURL extracts the redirect URL from the orderAndPay response.
func parseRedirectURL(resp []byte) (string, error) {
	var parsed struct {
		Code string `json:"code"`
		Data struct {
			RedirectURL string `json:"redirectUrl"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		return "", err
	}
	if parsed.Code != "APPLY_SUCCESS" {
		return "", fmt.Errorf("payermax checkout failed: %s", resp)
	}
	if parsed.Data.RedirectURL == "" {
		return "", fmt.Errorf("payermax: empty redirectUrl in %s", resp)
	}
	return parsed.Data.RedirectURL, nil
}

// RegisterRoutes is a no-op; PayerMax events are not wired through HTTP routes here.
func (c *Client) RegisterRoutes(mux *http.ServeMux, deliver func(ctx context.Context, e payment.Event) error) {
}
