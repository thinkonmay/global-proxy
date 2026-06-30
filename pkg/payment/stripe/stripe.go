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
	"github.com/thinkonmay/global-proxy/api/pkg/router"
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

// Charge starts a hosted Stripe Checkout session and returns its redirect URL.
func (c *Client) Charge(ctx context.Context, args payment.ChargeParams) (payment.Charge, error) {
	if c.secretKey == "" {
		return payment.Charge{}, fmt.Errorf("stripe secret not configured")
	}
	if strings.ToUpper(args.Money.Currency) != "USD" {
		return payment.Charge{}, fmt.Errorf("stripe only supports USD")
	}

	returnURL := strings.TrimSpace(args.ReturnURL)
	if returnURL == "" {
		returnURL = defaultReturnURL
	}
	cancelURL := strings.TrimSpace(args.CancelURL)
	if cancelURL == "" {
		cancelURL = returnURL
	}
	// Hosted checkout: no UIMode/RedirectOnCompletion; Stripe drives success/cancel via URLs.
	// ClientReferenceID lets us correlate the session to our txn via webhook metadata.
	sess, err := c.sc.V1CheckoutSessions.Create(ctx, &stripesdk.CheckoutSessionCreateParams{
		Mode:               stripesdk.String(string(stripesdk.CheckoutSessionModePayment)),
		SuccessURL:         stripesdk.String(returnURL),
		CancelURL:          stripesdk.String(cancelURL),
		ClientReferenceID:  stripesdk.String(args.IdempotencyKey),
		CustomerEmail:      optString(args.CustomerEmail),
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

// Subscribe starts a recurring Stripe Checkout session (Mode=subscription) and returns its
// redirect URL. The provider subscription id is unknown until checkout completes; it arrives
// via the checkout.session.completed webhook. SubscribeParams.IdempotencyKey is echoed as
// client_reference_id + subscription metadata so the webhook can correlate back to our row.
func (c *Client) Subscribe(ctx context.Context, args payment.SubscribeParams) (payment.Subscription, error) {
	if c.secretKey == "" {
		return payment.Subscription{}, fmt.Errorf("stripe secret not configured")
	}
	if strings.ToUpper(args.Money.Currency) != "USD" {
		return payment.Subscription{}, fmt.Errorf("stripe only supports USD")
	}
	interval := strings.ToLower(strings.TrimSpace(args.Interval))
	if interval == "" {
		interval = "month"
	}
	returnURL := strings.TrimSpace(args.ReturnURL)
	if returnURL == "" {
		returnURL = defaultReturnURL
	}
	sess, err := c.sc.V1CheckoutSessions.Create(ctx, &stripesdk.CheckoutSessionCreateParams{
		Mode:              stripesdk.String(string(stripesdk.CheckoutSessionModeSubscription)),
		SuccessURL:        stripesdk.String(returnURL),
		CancelURL:         stripesdk.String(returnURL),
		ClientReferenceID: stripesdk.String(args.IdempotencyKey),
		CustomerEmail:     optString(args.CustomerEmail),
		LineItems: []*stripesdk.CheckoutSessionCreateLineItemParams{{
			Quantity: stripesdk.Int64(1),
			PriceData: &stripesdk.CheckoutSessionCreateLineItemPriceDataParams{
				Currency:   stripesdk.String(strings.ToLower(args.Money.Currency)),
				UnitAmount: stripesdk.Int64(args.Money.Amount),
				Recurring: &stripesdk.CheckoutSessionCreateLineItemPriceDataRecurringParams{
					Interval: stripesdk.String(interval),
				},
				ProductData: &stripesdk.CheckoutSessionCreateLineItemPriceDataProductDataParams{
					Name: stripesdk.String("thinkmay"),
				},
			},
		}},
		SubscriptionData: &stripesdk.CheckoutSessionCreateSubscriptionDataParams{
			Metadata: map[string]string{
				"sub_intent": args.IdempotencyKey,
				"plan":       args.PlanRef,
			},
		},
	})
	if err != nil {
		return payment.Subscription{}, err
	}
	return payment.Subscription{Status: payment.StatusPending, RedirectURL: sess.URL}, nil
}

// GetSubscription retrieves a subscription and maps its status + current period end.
func (c *Client) GetSubscription(ctx context.Context, id string) (payment.Subscription, error) {
	if c.secretKey == "" {
		return payment.Subscription{}, fmt.Errorf("stripe secret not configured")
	}
	sub, err := c.sc.V1Subscriptions.Retrieve(ctx, id, nil)
	if err != nil {
		return payment.Subscription{}, err
	}
	return payment.Subscription{
		ID:        sub.ID,
		Status:    subStatus(sub.Status),
		PeriodEnd: subPeriodEnd(sub),
	}, nil
}

// CancelSubscription cancels a Stripe subscription immediately.
func (c *Client) CancelSubscription(ctx context.Context, id string) error {
	if c.secretKey == "" {
		return fmt.Errorf("stripe secret not configured")
	}
	_, err := c.sc.V1Subscriptions.Cancel(ctx, id, nil)
	return err
}

// subStatus maps a Stripe subscription status to a normalized payment.Status.
func subStatus(s stripesdk.SubscriptionStatus) payment.Status {
	switch s {
	case stripesdk.SubscriptionStatusActive, stripesdk.SubscriptionStatusTrialing:
		return payment.StatusActive
	case stripesdk.SubscriptionStatusCanceled:
		return payment.StatusCanceled
	case stripesdk.SubscriptionStatusPastDue, stripesdk.SubscriptionStatusUnpaid:
		return payment.StatusPastDue
	default:
		return payment.StatusPending
	}
}

// subPeriodEnd reads the current period end (unix seconds) from the first subscription item.
// In Stripe API 2025-08+, current_period_end lives on items, not the subscription object.
func subPeriodEnd(sub *stripesdk.Subscription) int64 {
	if sub != nil && sub.Items != nil && len(sub.Items.Data) > 0 {
		return sub.Items.Data[0].CurrentPeriodEnd
	}
	return 0
}

// optString returns nil for an empty string (Stripe rejects empty optional fields).
func optString(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

// invoiceSubID extracts the provider subscription id from an invoice's parent details.
func invoiceSubID(inv *stripesdk.Invoice) string {
	if inv.Parent != nil && inv.Parent.SubscriptionDetails != nil && inv.Parent.SubscriptionDetails.Subscription != nil {
		return inv.Parent.SubscriptionDetails.Subscription.ID
	}
	return ""
}

// invoicePeriodEnd reads the period end (unix seconds) from the first invoice line.
func invoicePeriodEnd(inv *stripesdk.Invoice) int64 {
	if inv.Lines != nil && len(inv.Lines.Data) > 0 && inv.Lines.Data[0].Period != nil {
		return inv.Lines.Data[0].Period.End
	}
	return 0
}

// RegisterRoutes mounts the Stripe webhook: verifies Stripe-Signature, then emits
// normalized payment.Events (charges + subscription lifecycle); unknown types are acked.
func (c *Client) RegisterRoutes(g *router.Group, deliver func(ctx context.Context, e payment.Event) error) {
	g.POST("/stripe", func(w http.ResponseWriter, r *http.Request) {
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
			if err := deliver(r.Context(), payment.Event{
				Kind:       payment.EventCharge,
				ProviderID: pi.ID,
				RefID:      txnID,
				Status:     payment.StatusSuccess,
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

		case "checkout.session.completed":
			var sess stripesdk.CheckoutSession
			if err := json.Unmarshal(stripeEvt.Data.Raw, &sess); err != nil {
				http.Error(w, "cannot parse checkout_session", http.StatusBadRequest)
				return
			}
			// Only subscription-mode sessions activate a subscription; one-time payment
			// sessions settle via payment_intent.succeeded above.
			if sess.Mode != stripesdk.CheckoutSessionModeSubscription {
				break
			}
			subID := ""
			if sess.Subscription != nil {
				subID = sess.Subscription.ID
			}
			if subID == "" || sess.ClientReferenceID == "" {
				http.Error(w, "missing subscription or client_reference_id", http.StatusBadRequest)
				return
			}
			// Fetch the subscription to learn the current period end; best-effort (the first
			// invoice.payment_succeeded will also carry it). Skipped without a secret key.
			var periodEnd int64
			if c.secretKey != "" {
				if sub, e := c.sc.V1Subscriptions.Retrieve(r.Context(), subID, nil); e == nil {
					periodEnd = subPeriodEnd(sub)
				}
			}
			if err := deliver(r.Context(), payment.Event{
				Kind:          payment.EventSubActivated,
				RefID:         sess.ClientReferenceID,
				ProviderSubID: subID,
				Status:        payment.StatusActive,
				PeriodEnd:     periodEnd,
			}); err != nil {
				http.Error(w, "failed to deliver event", http.StatusInternalServerError)
				return
			}

		case "invoice.payment_succeeded":
			var inv stripesdk.Invoice
			if err := json.Unmarshal(stripeEvt.Data.Raw, &inv); err != nil {
				http.Error(w, "cannot parse invoice", http.StatusBadRequest)
				return
			}
			// Initial-cycle invoices are handled by checkout.session.completed; only renewals here.
			if inv.BillingReason != stripesdk.InvoiceBillingReasonSubscriptionCycle {
				break
			}
			subID := invoiceSubID(&inv)
			if subID == "" {
				http.Error(w, "missing subscription on invoice", http.StatusBadRequest)
				return
			}
			if err := deliver(r.Context(), payment.Event{
				Kind:          payment.EventSubRenewed,
				ProviderSubID: subID,
				Status:        payment.StatusActive,
				PeriodEnd:     invoicePeriodEnd(&inv),
			}); err != nil {
				http.Error(w, "failed to deliver event", http.StatusInternalServerError)
				return
			}

		case "customer.subscription.deleted":
			var sub stripesdk.Subscription
			if err := json.Unmarshal(stripeEvt.Data.Raw, &sub); err != nil {
				http.Error(w, "cannot parse subscription", http.StatusBadRequest)
				return
			}
			if sub.ID == "" {
				http.Error(w, "missing subscription id", http.StatusBadRequest)
				return
			}
			if err := deliver(r.Context(), payment.Event{
				Kind:          payment.EventSubCanceled,
				ProviderSubID: sub.ID,
				Status:        payment.StatusCanceled,
			}); err != nil {
				http.Error(w, "failed to deliver event", http.StatusInternalServerError)
				return
			}

		case "invoice.payment_failed":
			var inv stripesdk.Invoice
			if err := json.Unmarshal(stripeEvt.Data.Raw, &inv); err != nil {
				http.Error(w, "cannot parse invoice", http.StatusBadRequest)
				return
			}
			subID := invoiceSubID(&inv)
			if subID == "" {
				break // not a subscription invoice
			}
			if err := deliver(r.Context(), payment.Event{
				Kind:          payment.EventSubCanceled,
				ProviderSubID: subID,
				Status:        payment.StatusPastDue,
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
