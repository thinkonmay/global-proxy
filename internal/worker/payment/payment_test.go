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
