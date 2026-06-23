package model

import (
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// PaymentEvent is the normalized provider callback the gateway publishes and the
// worker consumes to settle a transaction.
type PaymentEvent struct {
	Provider    string          `json:"provider"`
	ChargeID    string          `json:"charge_id"`           // provider-side id (pm/order/session)
	TxnID       int64           `json:"txn_id"`              // billing.transactions.id
	Status      string          `json:"status"`              // canonical: pending|processing|success|cancelled|failed
	Token       string          `json:"token,omitempty"`     // saved-card handle, if issued
	Raw         json.RawMessage `json:"raw,omitempty"`       // original payload for audit
	CustomerRef string          `json:"customer_ref,omitempty"` // provider customer id (Stripe cus_…)
	Brand       string          `json:"brand,omitempty"`        // saved-card brand
	Last4       string          `json:"last4,omitempty"`        // saved-card last 4
}

// PaymentMethodRow is a saved card persisted in billing.payment_methods.
type PaymentMethodRow struct {
	UserID      int64
	Provider    string
	CustomerRef string
	PMRef       string
	Brand       string
	Last4       string
	ExpMonth    int
	ExpYear     int
}

var TopicPaymentEvent = bus.NewTopic[PaymentEvent]("billing.payment.event")
var TopicPaymentDLQ = bus.NewTopic[PaymentEvent]("billing.payment.event.dlq")
