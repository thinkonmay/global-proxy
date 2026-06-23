package handler

import (
	"context"
	"net/http"
	"strconv"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// paymentDeliverFunc returns the deliver closure a provider calls from its
// webhook handler. It maps a normalized payment.Event to a model.PaymentEvent
// and publishes it for the worker to settle.
func paymentDeliverFunc(eventBus bus.Client, provider string) func(context.Context, payment.Event) error {
	return func(ctx context.Context, e payment.Event) error {
		// non-numeric ID (should never occur for SePay, whose ID is the txn id) yields TxnID=0; the worker rejects unknown ids via DB lookup
		txnID, _ := strconv.ParseInt(e.ID, 10, 64)
		return bus.Publish(ctx, eventBus, model.TopicPaymentEvent, model.PaymentEvent{
			Provider:    provider,
			ChargeID:    e.ID,
			TxnID:       txnID,
			Status:      string(e.Status),
			Token:       e.Token,
			CustomerRef: e.CustomerRef,
			Brand:       e.Brand,
			Last4:       e.Last4,
		})
	}
}

// RegisterPaymentWebhooks mounts every provider's webhook routes on the mux.
// Returns early if eventBus is nil (dev mode, no bus).
func RegisterPaymentWebhooks(mux *http.ServeMux, reg *registry.Registry, eventBus bus.Client) {
	if eventBus == nil {
		return // no bus (dev) -> webhooks disabled; poll fallback still settles
	}
	for name, client := range reg.All() {
		client.RegisterRoutes(mux, paymentDeliverFunc(eventBus, name))
	}
}
