package payos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	payossdk "github.com/payOSHQ/payos-lib-golang/v2"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

// returnURL and cancelURL are the default redirect targets, ported from legacy.
const (
	returnURL = "https://thinkmay.net"
	cancelURL = "https://thinkmay.net"
)

var _ payment.Client = (*Client)(nil)

// Config holds PayOS credentials, mirroring the legacy payOSConfig.
type Config struct {
	ClientID     string
	ClientSecret string
	ChecksumKey  string
}

// Client is the PayOS payment provider.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a PayOS client backed by its own HTTP client.
func New(cfg Config) payment.Client {
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// Name identifies the provider for registry lookup.
func (c *Client) Name() string { return "payos" }

// sdk constructs the PayOS SDK client, guarding against incomplete credentials.
func (c *Client) sdk() (*payossdk.PayOS, error) {
	if c.cfg.ClientID == "" || c.cfg.ClientSecret == "" || c.cfg.ChecksumKey == "" {
		return nil, fmt.Errorf("payos config incomplete")
	}
	return payossdk.NewPayOS(&payossdk.PayOSOptions{
		ClientId:    c.cfg.ClientID,
		ApiKey:      c.cfg.ClientSecret,
		ChecksumKey: c.cfg.ChecksumKey,
		HTTPClient:  c.http,
		Timeout:     15 * time.Second,
	})
}

// Charge creates a PayOS payment link; OrderCode is the caller ref.
func (c *Client) Charge(ctx context.Context, args payment.ChargeParams) (payment.Charge, error) {
	client, err := c.sdk()
	if err != nil {
		return payment.Charge{}, err
	}

	orderCode, err := strconv.ParseInt(args.IdempotencyKey, 10, 64)
	if err != nil {
		return payment.Charge{}, fmt.Errorf("payos: invalid ref id %q: %w", args.IdempotencyKey, err)
	}

	// Money.Amount is minor units; VND has no minor unit so use it as-is.
	amt := int(args.Money.Amount)
	desc := payosDescription(args.Description, args.Money.Amount)

	ret := args.ReturnURL
	if ret == "" {
		ret = returnURL
	}
	cancel := args.ReturnURL
	if cancel == "" {
		cancel = cancelURL
	}

	// PayOS payment links expire 15 minutes after creation, like legacy.
	expiredAt := int(time.Now().Add(15 * time.Minute).Unix())

	resp, err := client.PaymentRequests.Create(ctx, payossdk.CreatePaymentLinkRequest{
		OrderCode:   orderCode,
		Amount:      amt,
		Description: desc,
		CancelUrl:   cancel,
		ReturnUrl:   ret,
		ExpiredAt:   &expiredAt,
		Items: []payossdk.PaymentLinkItem{{
			Name: "custom", Price: amt, Quantity: 1,
		}},
	})
	if err != nil {
		return payment.Charge{}, err
	}

	b, _ := json.Marshal(resp)
	return payment.Charge{
		ID:          args.IdempotencyKey,
		Status:      payment.StatusPending,
		RedirectURL: resp.CheckoutUrl,
		Detail:      b,
	}, nil
}

// GetCharge fetches the current state of a charge by its order code.
func (c *Client) GetCharge(ctx context.Context, id string) (payment.Charge, error) {
	client, err := c.sdk()
	if err != nil {
		return payment.Charge{}, err
	}

	orderCode, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return payment.Charge{}, fmt.Errorf("payos: invalid charge id %q: %w", id, err)
	}

	link, err := client.PaymentRequests.Get(ctx, orderCode)
	if err != nil {
		return payment.Charge{}, err
	}

	return payment.Charge{
		ID:     id,
		Status: mapStatus(string(link.Status)),
	}, nil
}

// RegisterRoutes is a no-op; PayOS state is observed by polling, not webhooks.
func (c *Client) RegisterRoutes(mux *http.ServeMux, deliver func(ctx context.Context, e payment.Event) error) {
}

// payosDescription derives a short PayOS description prefix, ported from legacy.
func payosDescription(email string, amount int64) string {
	prefix := email
	if i := strings.Index(email, "@"); i >= 0 {
		prefix = email[:i]
	}
	if len(prefix) > 15 {
		prefix = prefix[:15]
	}
	return prefix + strconv.FormatInt(amount, 10)
}

// mapStatus maps a PayOS provider status to a normalized payment.Status.
func mapStatus(status string) payment.Status {
	switch strings.ToUpper(status) {
	case "PAID":
		return payment.StatusSuccess
	case "CANCELLED", "EXPIRED":
		return payment.StatusCanceled
	case "PENDING", "PROCESSING":
		return payment.StatusPending
	default:
		return payment.StatusPending
	}
}
