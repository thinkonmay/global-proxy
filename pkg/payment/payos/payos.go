package payos

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	payossdk "github.com/payOSHQ/payos-lib-golang/v2"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
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

// Subscribe is unsupported: PayOS has no recurring billing here.
func (c *Client) Subscribe(ctx context.Context, args payment.SubscribeParams) (payment.Subscription, error) {
	return payment.Subscription{}, payment.ErrNotSupported
}

// GetSubscription is unsupported for PayOS.
func (c *Client) GetSubscription(ctx context.Context, id string) (payment.Subscription, error) {
	return payment.Subscription{}, payment.ErrNotSupported
}

// CancelSubscription is unsupported for PayOS.
func (c *Client) CancelSubscription(ctx context.Context, id string) error {
	return payment.ErrNotSupported
}

// RegisterRoutes mounts the PayOS webhook. PayOS only posts settled payments;
// the poll fallback still covers cancel/expire, which are not delivered here.
func (c *Client) RegisterRoutes(g *router.Group, deliver func(ctx context.Context, e payment.Event) error) {
	g.POST("/payos", func(w http.ResponseWriter, r *http.Request) {
		client, err := c.sdk()
		if err != nil {
			http.Error(w, "payos not configured", http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}

		// VerifyData recomputes the HMAC signature over the data object; it needs the raw map.
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if _, err := client.Webhooks.VerifyData(r.Context(), raw); err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		var hook payossdk.Webhook
		if err := json.Unmarshal(body, &hook); err != nil || hook.Data == nil {
			http.Error(w, "invalid webhook data", http.StatusBadRequest)
			return
		}
		// data.code "00" is paid; ack anything else without crediting.
		if hook.Data.Code != "00" {
			w.WriteHeader(http.StatusOK)
			return
		}

		ref := strconv.FormatInt(hook.Data.OrderCode, 10)
		if err := deliver(r.Context(), payment.Event{
			Kind:       payment.EventCharge,
			ProviderID: ref,
			RefID:      ref,
			Status:     payment.StatusSuccess,
		}); err != nil {
			slog.Warn("payos webhook: deliver", "order_code", ref, "err", err)
			http.Error(w, "failed to deliver event", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// payosDescription derives a short PayOS description prefix, ported from legacy.
func payosDescription(email string, amount int64) string {
	prefix := email
	if before, _, ok := strings.Cut(email, "@"); ok {
		prefix = before
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
