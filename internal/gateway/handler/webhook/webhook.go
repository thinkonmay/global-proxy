package webhook

import (
	"context"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// RegisterPaymentWebhooks mounts every provider's webhook routes on the mux.
// Returns early if eventBus is nil (dev mode, no bus).
func RegisterPaymentWebhooks(mux *http.ServeMux, reg *registry.Registry, eventBus bus.Client) {
	if eventBus == nil {
		return // no bus (dev) -> webhooks disabled; poll fallback still settles
	}
	for name, client := range reg.All() {
		client.RegisterRoutes(mux, func(ctx context.Context, e payment.Event) error {
			return bus.Publish(ctx, eventBus, model.TopicPayment, model.PaymentMsg{
				Event:    e,
				Provider: name,
			})
		})
	}
}
