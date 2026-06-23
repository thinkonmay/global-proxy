package handler

import (
	"context"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
)

type fakeGetCharger struct {
	payment.Client
	st payment.Status
}

func (f fakeGetCharger) Name() string { return "payos" }
func (f fakeGetCharger) GetCharge(_ context.Context, _ string) (payment.Charge, error) {
	return payment.Charge{Status: f.st}, nil
}

func TestPollSettlesTerminal(t *testing.T) {
	var settled []string
	h := &Handler{
		idem: idempotency.New(idempotency.NewMemStore()),
		settleRPC: func(_ context.Context, _ string, args map[string]any) error {
			settled = append(settled, args["p_status"].(string))
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
	if len(settled) != 1 || settled[0] != "success" {
		t.Fatalf("settled = %v, want [success]", settled)
	}
}
