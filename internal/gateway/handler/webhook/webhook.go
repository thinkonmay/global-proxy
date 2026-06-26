package webhook

import (
	"context"
	"fmt"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// RegisterPaymentWebhooks mounts every provider's webhook routes on the mux.
// Routes are always mounted: if eventBus is nil the deliver callback errors, so
// the provider gets a 5xx and retries — instead of a permanent 404 that silently
// drops the settlement (the poll fallback does not cover subscription events).
func RegisterPaymentWebhooks(mux *http.ServeMux, reg *registry.Registry, eventBus bus.Client) {
	g := router.New(mux, payment.WebhookPathPrefix)
	for name, client := range reg.All() {
		client.RegisterRoutes(g, func(ctx context.Context, e payment.Event) error {
			if eventBus == nil {
				return fmt.Errorf("payment webhook %q: event bus not configured", name)
			}
			return bus.Publish(ctx, eventBus, model.TopicPayment, model.PaymentMsg{
				Event:    e,
				Provider: name,
			})
		})
	}
}
