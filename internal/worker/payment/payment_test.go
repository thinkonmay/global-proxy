package payment

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestHandlePaymentEventSettlesOnce(t *testing.T) {
	// Regression: duplicate webhook delivery must not double-settle a request.
	var calls int
	rpc := func(ctx context.Context, fn string, args map[string]any) error {
		if fn == "settle_request" {
			calls++
		}
		return nil
	}
	h := &Handler{idem: idempotency.New(idempotency.NewMemStore()), settleRPC: rpc}
	ev := model.PaymentMsg{
		Provider: "payos",
		Event:    payment.Event{RefID: "5", Status: "success", ProviderID: "5"},
	}
	_ = h.handlePaymentEvent(context.Background(), ev)
	_ = h.handlePaymentEvent(context.Background(), ev) // duplicate delivery
	if calls != 1 {
		t.Fatalf("settle calls = %d, want 1 (idempotent)", calls)
	}
}

func TestPollDuplicateTickSettlesOnce(t *testing.T) {
	var settled int
	h := &Handler{
		idem: idempotency.New(idempotency.NewMemStore()),
		settleRPC: func(_ context.Context, _ string, args map[string]any) error {
			if args["p_status"] == "success" {
				settled++
			}
			return nil
		},
		listPending: func(_ context.Context) ([]pendingTxn, error) {
			return []pendingTxn{{ID: 3, Provider: "payos"}}, nil
		},
	}
	reg := registry.NewRegistryWith(map[string]payment.Client{"payos": fakeGetCharger{st: payment.StatusSuccess}})
	if err := h.pollOnce(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := h.pollOnce(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if settled != 1 {
		t.Fatalf("settled = %d, want 1 (idempotent poll redelivery)", settled)
	}
}

func TestChargeEventAndPollRace(t *testing.T) {
	var settled int
	h := &Handler{
		idem: idempotency.New(idempotency.NewMemStore()),
		settleRPC: func(_ context.Context, fn string, args map[string]any) error {
			if fn == "settle_request" {
				settled++
			}
			return nil
		},
		listPending: func(_ context.Context) ([]pendingTxn, error) {
			return []pendingTxn{{ID: 5, Provider: "payos"}}, nil
		},
	}
	ev := model.PaymentMsg{
		Provider: "payos",
		Event:    payment.Event{RefID: "5", Status: "success", ProviderID: "pi_1"},
	}
	reg := registry.NewRegistryWith(map[string]payment.Client{"payos": fakeGetCharger{st: payment.StatusSuccess}})
	if err := h.handlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if err := h.pollOnce(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if settled != 1 {
		t.Fatalf("settle_request calls = %d, want 1 (event + poll race)", settled)
	}
}

// On a successful charge settle, the worker publishes the status to TopicEvent
// on the payment domain, routed to the deposit owner, so the gateway can push it
// to that user's /v1/event/payment stream.
func TestSettleChargePublishesEvent(t *testing.T) {
	eventBus := busmemory.New(nil)
	var mu sync.Mutex
	var got model.EventRaw
	bus.Subscribe(eventBus, model.TopicEvent, "test-event", func(_ context.Context, m model.EventRaw) error {
		mu.Lock()
		got = m
		mu.Unlock()
		return nil
	})

	h := &Handler{
		idem:        idempotency.New(idempotency.NewMemStore()),
		eventBus:    eventBus,
		settleRPC:   func(context.Context, string, map[string]any) error { return nil },
		lookupEmail: func(context.Context, string) string { return "user@example.com" },
	}
	ev := model.PaymentMsg{Event: payment.Event{RefID: "42", Status: "success", ProviderID: "pi_1"}}
	if err := h.handlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	eventBus.Wait()

	mu.Lock()
	defer mu.Unlock()
	if got.Domain != "payment" {
		t.Fatalf("domain = %q, want %q", got.Domain, "payment")
	}
	if got.Recipient != "user@example.com" {
		t.Fatalf("recipient = %q, want user@example.com", got.Recipient)
	}
	var p paymentEvent
	if err := json.Unmarshal(got.Data, &p); err != nil {
		t.Fatal(err)
	}
	if p.TransactionID != "42" || p.Status != "success" {
		t.Fatalf("payload = %+v, want {42 success}", p)
	}
}
