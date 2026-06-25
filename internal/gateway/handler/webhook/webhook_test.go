package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type fakeWebhookProvider struct{}

func (fakeWebhookProvider) Name() string { return "testpay" }
func (fakeWebhookProvider) Charge(context.Context, payment.ChargeParams) (payment.Charge, error) {
	return payment.Charge{}, payment.ErrNotSupported
}
func (fakeWebhookProvider) GetCharge(context.Context, string) (payment.Charge, error) {
	return payment.Charge{}, payment.ErrNotSupported
}
func (fakeWebhookProvider) Subscribe(context.Context, payment.SubscribeParams) (payment.Subscription, error) {
	return payment.Subscription{}, payment.ErrNotSupported
}
func (fakeWebhookProvider) GetSubscription(context.Context, string) (payment.Subscription, error) {
	return payment.Subscription{}, payment.ErrNotSupported
}
func (fakeWebhookProvider) CancelSubscription(context.Context, string) error {
	return payment.ErrNotSupported
}
func (fakeWebhookProvider) RegisterRoutes(mux *http.ServeMux, deliver func(context.Context, payment.Event) error) {
	mux.HandleFunc("POST /api/v1/payment/webhook/testpay", func(w http.ResponseWriter, r *http.Request) {
		if err := deliver(r.Context(), payment.Event{
			RefID:  "txn-1",
			Status: payment.StatusSuccess,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestRegisterPaymentWebhooksPublishesToBus(t *testing.T) {
	eventBus := busmemory.New(nil)
	reg := registry.NewRegistryWith(map[string]payment.Client{
		"testpay": fakeWebhookProvider{},
	})

	var mu sync.Mutex
	var got model.PaymentMsg
	bus.Subscribe(eventBus, model.TopicPayment, "test", func(_ context.Context, msg model.PaymentMsg) error {
		mu.Lock()
		got = msg
		mu.Unlock()
		return nil
	})

	mux := http.NewServeMux()
	RegisterPaymentWebhooks(mux, reg, eventBus)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/testpay", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	eventBus.Wait()

	if rec.Code != http.StatusOK {
		t.Fatalf("webhook status: %d body: %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Provider != "testpay" || got.Event.RefID != "txn-1" || got.Event.Status != payment.StatusSuccess {
		t.Fatalf("published msg: %+v", got)
	}
}

// With no bus the route is still mounted; deliver errors so the provider gets a
// retryable 5xx rather than a permanent 404 that silently drops the settlement.
func TestRegisterPaymentWebhooksMountedWithoutBus(t *testing.T) {
	reg := registry.NewRegistryWith(map[string]payment.Client{
		"testpay": fakeWebhookProvider{},
	})
	mux := http.NewServeMux()
	RegisterPaymentWebhooks(mux, reg, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/testpay", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatalf("route should be mounted even without a bus, got 404")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (retryable) when bus nil, got %d", rec.Code)
	}
}
