package payment

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

// ErrNotSupported is returned for an operation a provider does not implement.
var ErrNotSupported = errors.New("payment: operation not supported by provider")

// WebhookPathPrefix is the shared route prefix for provider webhook callbacks
// (full URL: WebhookPathPrefix + "/<provider>"); changing it breaks the URLs
// registered in each provider's dashboard.
const WebhookPathPrefix = "/api/v1/payment/webhook"

// Status is the normalized lifecycle state of a charge or subscription.
type Status string

const (
	StatusPending    Status = "pending"    // in progress
	StatusProcessing Status = "processing" // processing by provider
	StatusSuccess    Status = "success"    // completed
	StatusFailed     Status = "failed"     // system failure or expired
	StatusCanceled   Status = "cancelled"  // canceled by user
	StatusActive     Status = "active"     // subscription active (recurring)
	StatusPastDue    Status = "past_due"   // subscription invoice unpaid
)

// Money is an amount in its provider currency, in minor units (cents; VND/IDR have none),
// pre-converted via ExchangeRate.
type Money struct {
	Amount   int64
	Currency string
}

// Charge is the result of a charge operation, keyed by ID.
type Charge struct {
	ID          string
	Status      Status
	RedirectURL string          // hosted checkout redirect URL
	Detail      json.RawMessage // provider-specific client payload (raw provider response)
}

// ChargeParams initiates a one-time hosted-checkout charge.
type ChargeParams struct {
	IdempotencyKey string // stable order key; dedupes retries and correlates webhooks/polls
	Money          Money
	Description    string
	CustomerEmail  string // prefills the hosted-checkout email field (Stripe only); empty → user enters it
	ReturnURL      string
	CancelURL      string // where the provider sends the user on cancel; empty → ReturnURL (Stripe only)
	Method         string // optional provider payment-method/channel code to pre-select (e.g. PayerMax "OVO"/"DANA"); empty → provider/hosted page decides
}

// SubscribeParams initiates a recurring subscription (provider-hosted billing).
type SubscribeParams struct {
	IdempotencyKey string // local subscription-intent id; correlates webhooks back to our row
	Money          Money  // price charged per interval
	Interval       string // billing interval: "month" | "year"
	PlanRef        string // local plan name (e.g. month1/month2); echoed in provider metadata
	CustomerEmail  string // billed customer's email
	CustomerID     string // bind checkout to an existing provider customer (Stripe test clocks); honored only in test mode
	Description    string
	ReturnURL      string
}

// Subscription is the result of a subscribe operation, keyed by ID.
type Subscription struct {
	ID          string // provider subscription id (e.g. Stripe sub_…); empty until activated
	Status      Status
	RedirectURL string // hosted checkout URL for initial activation
	PeriodEnd   int64  // current period end (unix seconds); drives local plan expiry
}

// EventKind names which resource a webhook Event refers to.
type EventKind string

const (
	EventCharge       EventKind = "charge"        // one-time charge settled
	EventSubActivated EventKind = "sub_activated" // subscription initial checkout completed
	EventSubRenewed   EventKind = "sub_renewed"   // subscription invoice paid for a new cycle
	EventSubCanceled  EventKind = "sub_canceled"  // subscription canceled or invoice failed
)

// Event is a normalized webhook callback decoded from a provider payload.
type Event struct {
	Kind          EventKind
	ProviderID    string // provider's own charge id (e.g. Stripe pi_…)
	RefID         string // our internal id, echoed back by the provider (txn / subscription-intent id)
	ProviderSubID string // provider subscription id (e.g. Stripe sub_…) for EventSub* kinds
	Status        Status
	PeriodEnd     int64 // subscription current period end (unix seconds) for EventSub* kinds
}

// Client is one payment provider. Unsupported operations return ErrNotSupported.
type Client interface {
	// Name identifies the provider for registry lookup.
	Name() string
	// Charge starts a one-time hosted-checkout charge and returns its redirect URL.
	Charge(ctx context.Context, args ChargeParams) (Charge, error)
	// GetCharge fetches the current state of a charge.
	GetCharge(ctx context.Context, id string) (Charge, error)
	// Subscribe starts a recurring subscription checkout; ErrNotSupported if the provider has none.
	Subscribe(ctx context.Context, args SubscribeParams) (Subscription, error)
	// GetSubscription fetches the current state of a subscription; ErrNotSupported if unsupported.
	GetSubscription(ctx context.Context, id string) (Subscription, error)
	// CancelSubscription cancels a subscription; ErrNotSupported if unsupported.
	CancelSubscription(ctx context.Context, id string) error
	// RegisterRoutes mounts the webhook handler on g (scoped to WebhookPathPrefix);
	// the provider adds only its own subpath, e.g. "/stripe".
	RegisterRoutes(g *router.Group, deliver func(ctx context.Context, e Event) error)
}
