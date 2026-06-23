// Package stripe implements the payment.Client interface backed by Stripe Checkout.
package stripe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	stripesdk "github.com/stripe/stripe-go/v82"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

// defaultReturnURL is used for hosted checkout when args.ReturnURL is empty.
const defaultReturnURL = "https://thinkmay.net"

// Config holds the Stripe provider credentials.
type Config struct {
	SecretKey     string
	WebhookSecret string
}

// Client is a Stripe-backed payment provider.
type Client struct {
	secretKey     string
	webhookSecret string
	sc            *stripesdk.Client
}

// compile-time check that Client satisfies payment.Client.
var _ payment.Client = (*Client)(nil)

// New builds a Stripe client with its own 15s HTTP client wired into the SDK backends.
func New(cfg Config) payment.Client {
	httpClient := &http.Client{Timeout: 15 * time.Second}
	backends := stripesdk.NewBackendsWithConfig(&stripesdk.BackendConfig{
		HTTPClient: httpClient,
	})
	return &Client{
		secretKey:     cfg.SecretKey,
		webhookSecret: cfg.WebhookSecret,
		sc:            stripesdk.NewClient(cfg.SecretKey, stripesdk.WithBackends(backends)),
	}
}

// Name identifies the provider for registry lookup.
func (c *Client) Name() string { return "stripe" }

// mapPI maps a Stripe PaymentIntent status string to a normalized payment.Status.
// "succeeded" → StatusSuccess; "canceled" → StatusCanceled; everything else → StatusPending.
func mapPI(status string) payment.Status {
	switch status {
	case "succeeded":
		return payment.StatusSuccess
	case "canceled":
		return payment.StatusCanceled
	default:
		return payment.StatusPending
	}
}

// Charge charges a saved card off-session when args.Token is set, or starts a
// hosted Stripe Checkout session and returns its redirect URL otherwise.
func (c *Client) Charge(ctx context.Context, args payment.ChargeParams) (payment.Charge, error) {
	if c.secretKey == "" {
		return payment.Charge{}, fmt.Errorf("stripe secret not configured")
	}
	if strings.ToUpper(args.Money.Currency) != "USD" {
		return payment.Charge{}, fmt.Errorf("stripe only supports USD")
	}
	// Off-session branch: charge a saved card without user interaction.
	// Token holds the provider payment-method handle (e.g. pm_…) from the vault layer.
	// CustomerRef must be set to the Stripe Customer ID (cus_…) that owns the payment method.
	// NOTE: The PaymentIntents.Create call here requires live Stripe credentials;
	// it is NOT covered by unit tests — verify manually with a Stripe test-mode key.
	if args.Token != "" {
		pi, err := c.sc.V1PaymentIntents.Create(ctx, &stripesdk.PaymentIntentCreateParams{
			Amount:        new(args.Money.Amount),
			Currency:      new(strings.ToLower(args.Money.Currency)),
			Customer:      new(args.CustomerRef),
			PaymentMethod: new(args.Token),
			OffSession:    new(true),
			Confirm:       new(true),
			Metadata: map[string]string{
				"txn_id": args.IdempotencyKey,
			},
		})
		if err != nil {
			return payment.Charge{}, err
		}
		ch := payment.Charge{ID: pi.ID, Status: mapPI(string(pi.Status))}
		if pi.NextAction != nil && pi.NextAction.RedirectToURL != nil {
			ch.RedirectURL = pi.NextAction.RedirectToURL.URL
		}
		return ch, nil
	}

	returnURL := strings.TrimSpace(args.ReturnURL)
	if returnURL == "" {
		returnURL = defaultReturnURL
	}
	// Hosted checkout: no UIMode/RedirectOnCompletion; Stripe drives success/cancel via URLs.
	// ClientReferenceID lets us correlate the session to our txn via webhook metadata.
	// CustomerCreation="always" ensures a Stripe Customer is created so the card can be saved.
	// PaymentIntentData.SetupFutureUsage="off_session" attaches the PM to the Customer.
	sess, err := c.sc.V1CheckoutSessions.Create(ctx, &stripesdk.CheckoutSessionCreateParams{
		Mode:               stripesdk.String(string(stripesdk.CheckoutSessionModePayment)),
		SuccessURL:         stripesdk.String(returnURL),
		CancelURL:          stripesdk.String(returnURL),
		ClientReferenceID:  stripesdk.String(args.IdempotencyKey),
		CustomerCreation:   stripesdk.String("always"),
		PaymentMethodTypes: []*string{stripesdk.String("card")},
		LineItems: []*stripesdk.CheckoutSessionCreateLineItemParams{{
			Quantity: stripesdk.Int64(1),
			PriceData: &stripesdk.CheckoutSessionCreateLineItemPriceDataParams{
				Currency:   stripesdk.String(strings.ToLower(args.Money.Currency)),
				UnitAmount: stripesdk.Int64(args.Money.Amount),
				ProductData: &stripesdk.CheckoutSessionCreateLineItemPriceDataProductDataParams{
					Name: stripesdk.String("thinkmay"),
				},
			},
		}},
		PaymentIntentData: &stripesdk.CheckoutSessionCreatePaymentIntentDataParams{
			SetupFutureUsage: stripesdk.String("off_session"),
			Metadata: map[string]string{
				"txn_id": args.IdempotencyKey,
			},
		},
	})
	if err != nil {
		return payment.Charge{}, err
	}
	return payment.Charge{
		ID:          sess.ID,
		Status:      payment.StatusPending,
		RedirectURL: sess.URL,
	}, nil
}

// GetCharge retrieves a checkout session and maps its payment status.
func (c *Client) GetCharge(ctx context.Context, id string) (payment.Charge, error) {
	if c.secretKey == "" {
		return payment.Charge{}, fmt.Errorf("stripe secret not configured")
	}
	sess, err := c.sc.V1CheckoutSessions.Retrieve(ctx, id, nil)
	if err != nil {
		return payment.Charge{}, err
	}
	status := payment.StatusPending
	if sess.PaymentStatus == stripesdk.CheckoutSessionPaymentStatusPaid {
		status = payment.StatusSuccess
	}
	return payment.Charge{ID: id, Status: status}, nil
}

// RegisterRoutes mounts POST /api/v1/payment/webhook/stripe.
// It verifies the Stripe-Signature header with the configured webhook secret,
// then emits normalized payment.Events for payment_intent.succeeded and
// payment_intent.payment_failed. Unknown event types are acknowledged silently.
func (c *Client) RegisterRoutes(mux *http.ServeMux, deliver func(ctx context.Context, e payment.Event) error) {
	mux.HandleFunc("POST /api/v1/payment/webhook/stripe", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}

		sigHeader := r.Header.Get("Stripe-Signature")
		// ConstructEvent verifies signature, checks timestamp tolerance, and parses the Event.
		// WithIgnoreAPIVersionMismatch is not used — we want strict version validation in tests.
		stripeEvt, err := stripesdk.ConstructEvent(body, sigHeader, c.webhookSecret)
		if err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		switch stripeEvt.Type {
		case "payment_intent.succeeded":
			var pi stripesdk.PaymentIntent
			if err := json.Unmarshal(stripeEvt.Data.Raw, &pi); err != nil {
				http.Error(w, "cannot parse payment_intent", http.StatusBadRequest)
				return
			}
			txnID := pi.Metadata["txn_id"]
			if txnID == "" {
				http.Error(w, "missing txn_id in metadata", http.StatusBadRequest)
				return
			}
			pmID := ""
			if pi.PaymentMethod != nil {
				pmID = pi.PaymentMethod.ID
			}
			cusID := ""
			if pi.Customer != nil {
				cusID = pi.Customer.ID
			}
			if err := deliver(r.Context(), payment.Event{
				Kind:        payment.EventCharge,
				ProviderID:  pi.ID,
				RefID:       txnID,
				Status:      payment.StatusSuccess,
				Token:       pmID,
				CustomerRef: cusID,
			}); err != nil {
				http.Error(w, "failed to deliver event", http.StatusInternalServerError)
				return
			}

		case "payment_intent.payment_failed":
			var pi stripesdk.PaymentIntent
			if err := json.Unmarshal(stripeEvt.Data.Raw, &pi); err != nil {
				http.Error(w, "cannot parse payment_intent", http.StatusBadRequest)
				return
			}
			txnID := pi.Metadata["txn_id"]
			if txnID == "" {
				http.Error(w, "missing txn_id in metadata", http.StatusBadRequest)
				return
			}
			if err := deliver(r.Context(), payment.Event{
				Kind:       payment.EventCharge,
				ProviderID: pi.ID,
				RefID:      txnID,
				Status:     payment.StatusFailed,
			}); err != nil {
				http.Error(w, "failed to deliver event", http.StatusInternalServerError)
				return
			}

		default:
			// Ignore unknown event types; return 200 to prevent Stripe retries.
		}

		w.WriteHeader(http.StatusOK)
	})
}
