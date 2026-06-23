package handler

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestDeliverPublishesPaymentEvent(t *testing.T) {
	mem := busmemory.New(slog.Default())
	got := make(chan model.PaymentEvent, 1)
	bus.Subscribe(mem, model.TopicPaymentEvent, "test", func(_ context.Context, e model.PaymentEvent) error {
		got <- e
		return nil
	})
	deliver := paymentDeliverFunc(mem, "sepay")
	err := deliver(context.Background(), payment.Event{Kind: payment.EventCharge, ID: "42", Status: payment.StatusSuccess})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		if e.TxnID != 42 || e.Status != "success" || e.Provider != "sepay" || e.ChargeID != "42" {
			t.Fatalf("event = %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no event published")
	}
}
