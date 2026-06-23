package payment

import (
	"context"
	"testing"

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

// TestHandlePaymentEventStoresCard verifies that:
//   - saveCard is called once on a successful settle with a token.
//   - A redelivery of the same event does NOT call saveCard again (idempotency guard).
//   - An event with an empty Token does NOT call saveCard.
func TestHandlePaymentEventStoresCard(t *testing.T) {
	noopRPC := func(_ context.Context, _ string, _ map[string]any) error { return nil }

	t.Run("calls saveCard once on first delivery", func(t *testing.T) {
		var saveCardCalls int
		h := &Handler{
			idem:      idempotency.New(idempotency.NewMemStore()),
			settleRPC: noopRPC,
			saveCard: func(_ context.Context, _ model.PaymentMsg) error {
				saveCardCalls++
				return nil
			},
		}
		ev := model.PaymentMsg{
			Event:    payment.Event{RefID: "1", Status: "success", Token: "pm_1", CustomerRef: "cus_1"},
			Provider: "stripe",
		}
		if err := h.handlePaymentEvent(context.Background(), ev); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if saveCardCalls != 1 {
			t.Fatalf("saveCard calls = %d, want 1", saveCardCalls)
		}
	})

	t.Run("redelivery does not call saveCard again", func(t *testing.T) {
		var saveCardCalls int
		h := &Handler{
			idem:      idempotency.New(idempotency.NewMemStore()),
			settleRPC: noopRPC,
			saveCard: func(_ context.Context, _ model.PaymentMsg) error {
				saveCardCalls++
				return nil
			},
		}
		ev := model.PaymentMsg{
			Event:    payment.Event{RefID: "2", Status: "success", Token: "pm_2", CustomerRef: "cus_2"},
			Provider: "stripe",
		}
		_ = h.handlePaymentEvent(context.Background(), ev)
		_ = h.handlePaymentEvent(context.Background(), ev) // duplicate delivery
		if saveCardCalls != 1 {
			t.Fatalf("saveCard calls after redelivery = %d, want 1", saveCardCalls)
		}
	})

	t.Run("empty token does not call saveCard", func(t *testing.T) {
		var saveCardCalls int
		h := &Handler{
			idem:      idempotency.New(idempotency.NewMemStore()),
			settleRPC: noopRPC,
			saveCard: func(_ context.Context, _ model.PaymentMsg) error {
				saveCardCalls++
				return nil
			},
		}
		ev := model.PaymentMsg{Event: payment.Event{RefID: "3", Status: "success", Token: ""}, Provider: "stripe"}
		_ = h.handlePaymentEvent(context.Background(), ev)
		if saveCardCalls != 0 {
			t.Fatalf("saveCard calls = %d, want 0 (no token)", saveCardCalls)
		}
	})
}
