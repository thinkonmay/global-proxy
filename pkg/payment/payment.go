package payment

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// ErrNotSupported is returned for an operation a provider does not implement.
var ErrNotSupported = errors.New("payment: operation not supported by provider")

// Status is the normalized lifecycle state of a charge or refund.
type Status string

const (
	StatusPending    Status = "pending"    // in progress
	StatusProcessing Status = "processing" // processing by provider
	StatusSuccess    Status = "success"    // completed
	StatusFailed     Status = "failed"     // system failure or expired
	StatusCanceled   Status = "cancelled"  // canceled by user
)

// Money is an amount in its provider currency, in minor units (cents; VND/IDR have none),
// pre-converted via ExchangeRate.
type Money struct {
	Amount   int64
	Currency string
}

// ExchangeRate converts a unit rate between two currencies.
type ExchangeRate interface {
	Convert(ctx context.Context, from, to string) (float64, error)
}

// Charge is the result of a charge operation, keyed by ID.
type Charge struct {
	ID          string
	Status      Status
	RedirectURL string          // hosted checkout; empty for off-session charges
	Token       string          // reusable card handle the provider issued; stored by the vault layer
	Detail      json.RawMessage `json:"detail,omitempty"` // provider-specific client payload (raw provider response)
}

// Refund is the result of a refund operation.
type Refund struct {
	ID     string
	Status Status
}

// ChargeParams initiates a charge; set Token to charge a saved card off-session.
type ChargeParams struct {
	IdempotencyKey string // stable order key; dedupes retries and correlates webhooks/polls
	Money          Money
	Description    string
	ReturnURL      string
	Token          string // provider card handle from the vault layer; empty → hosted checkout
	CustomerRef    string // provider customer id (e.g. Stripe cus_…); required for off-session charges
}

// RefundParams refunds a charge; zero Money refunds the full amount.
type RefundParams struct {
	ChargeID string
	Money    Money
}

// EventKind names which resource a webhook Event refers to.
type EventKind string

const (
	EventCharge EventKind = "charge"
	EventRefund EventKind = "refund"
)

// Event is a normalized webhook callback decoded from a provider payload.
type Event struct {
	Kind        EventKind
	ID          string // our charge or refund handle
	Status      Status
	Token       string // reusable card handle, if the charge issued one
	CustomerRef string // provider customer id (e.g. Stripe cus_…)
	Brand       string // saved-card brand (e.g. "visa")
	Last4       string // saved-card last 4 digits
}

// Client is one payment provider. Unsupported operations return ErrNotSupported.
type Client interface {
	// Name identifies the provider for registry lookup.
	Name() string
	// Charge initiates a charge, or charges a saved card off-session if Token is set.
	Charge(ctx context.Context, args ChargeParams) (Charge, error)
	// GetCharge fetches the current state of a charge.
	GetCharge(ctx context.Context, id string) (Charge, error)
	// Refund refunds a prior charge.
	Refund(ctx context.Context, args RefundParams) (Refund, error)
	// RegisterRoutes wires the provider's HTTP routes and delivers decoded events.
	RegisterRoutes(mux *http.ServeMux, deliver func(ctx context.Context, e Event) error)
}
