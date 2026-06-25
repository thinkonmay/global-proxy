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
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestHandlePaymentEventSettlesOnce(t *testing.T) {
	var calls int
	rpc := func(ctx context.Context, fn string, args map[string]any) error {
		if fn == "settle_transaction" {
			calls++
		}
		return nil
	}
	h := &Handler{idem: idempotency.New(idempotency.NewMemStore()), settleRPC: rpc}
	ev := model.PaymentMsg{Event: payment.Event{RefID: "5", Status: "success", ProviderID: "5"}}
	_ = h.handlePaymentEvent(context.Background(), ev)
	_ = h.handlePaymentEvent(context.Background(), ev) // duplicate delivery
	if calls != 1 {
		t.Fatalf("settle calls = %d, want 1 (idempotent)", calls)
	}
}

// On a successful charge settle, the worker publishes the status to TopicSSE
// routed to the deposit owner, so the gateway can push it to that user's stream.
func TestSettleChargePublishesSSE(t *testing.T) {
	eventBus := busmemory.New(nil)
	var mu sync.Mutex
	var got model.SSERaw
	bus.Subscribe(eventBus, model.TopicSSE, "test-sse", func(_ context.Context, m model.SSERaw) error {
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
	if got.Type != ssePaymentType {
		t.Fatalf("type = %q, want %q", got.Type, ssePaymentType)
	}
	if got.Recipient != "user@example.com" {
		t.Fatalf("recipient = %q, want user@example.com", got.Recipient)
	}
	var p paymentSSE
	if err := json.Unmarshal(got.Data, &p); err != nil {
		t.Fatal(err)
	}
	if p.TransactionID != "42" || p.Status != "success" {
		t.Fatalf("payload = %+v, want {42 success}", p)
	}
}
