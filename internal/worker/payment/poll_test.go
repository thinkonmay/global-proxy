package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
)

type fakeGetCharger struct {
	payment.Client
	st     payment.Status
	err    error
	gotIDs *[]string
}

func (f fakeGetCharger) Name() string { return "payos" }
func (f fakeGetCharger) GetCharge(_ context.Context, id string) (payment.Charge, error) {
	if f.gotIDs != nil {
		*f.gotIDs = append(*f.gotIDs, id)
	}
	if f.err != nil {
		return payment.Charge{}, f.err
	}
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

// The poll must look the provider up by the stored charge_id, not the DB row id,
// because for stripe/payermax those differ.
func TestPollUsesStoredChargeID(t *testing.T) {
	var gotIDs []string
	h := &Handler{
		idem:      idempotency.New(idempotency.NewMemStore()),
		settleRPC: func(_ context.Context, _ string, _ map[string]any) error { return nil },
		listPending: func(_ context.Context) ([]pendingTxn, error) {
			data, _ := json.Marshal(map[string]any{"charge_id": "cs_test_123"})
			return []pendingTxn{{ID: 7, Provider: "payos", Data: data}}, nil
		},
	}
	reg := registry.NewRegistryWith(map[string]payment.Client{
		"payos": fakeGetCharger{st: payment.StatusSuccess, gotIDs: &gotIDs},
	})
	if err := h.pollOnce(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(gotIDs) != 1 || gotIDs[0] != "cs_test_123" {
		t.Fatalf("GetCharge id = %v, want [cs_test_123]", gotIDs)
	}
}

// An expired transaction the provider still reports non-terminal must settle as failed,
// so it does not linger forever once it falls past expire_at.
func TestPollFailsExpiredPending(t *testing.T) {
	var settled []string
	expired := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	h := &Handler{
		idem: idempotency.New(idempotency.NewMemStore()),
		settleRPC: func(_ context.Context, _ string, args map[string]any) error {
			settled = append(settled, args["p_status"].(string))
			return nil
		},
		listPending: func(_ context.Context) ([]pendingTxn, error) {
			return []pendingTxn{{ID: 9, Provider: "payos", ExpireAt: expired}}, nil
		},
	}
	reg := registry.NewRegistryWith(map[string]payment.Client{
		"payos": fakeGetCharger{st: payment.StatusPending},
	})
	if err := h.pollOnce(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(settled) != 1 || settled[0] != "failed" {
		t.Fatalf("settled = %v, want [failed]", settled)
	}
}

type fakeGetSubscriber struct {
	payment.Client
	sub payment.Subscription
	err error
}

func (f fakeGetSubscriber) Name() string { return "stripe" }
func (f fakeGetSubscriber) GetSubscription(_ context.Context, _ string) (payment.Subscription, error) {
	return f.sub, f.err
}

// An active provider subscription reconciles to a settle with its live period end.
func TestPollSubsSettlesActive(t *testing.T) {
	var got map[string]any
	h := &Handler{
		idem: idempotency.New(idempotency.NewMemStore()),
		settleRPC: func(_ context.Context, _ string, args map[string]any) error {
			got = args
			return nil
		},
		listSubs: func(_ context.Context) ([]pendingSub, error) {
			return []pendingSub{{ID: 1, Provider: "stripe", ProviderSubID: "sub_123"}}, nil
		},
	}
	reg := registry.NewRegistryWith(map[string]payment.Client{
		"stripe": fakeGetSubscriber{sub: payment.Subscription{Status: payment.StatusActive, PeriodEnd: 1750000000}},
	})
	if err := h.pollSubsOnce(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if got["p_status"] != "active" || got["p_period_end"] != int64(1750000000) || got["p_provider_sub_id"] != "sub_123" {
		t.Fatalf("settle args = %v", got)
	}
}

// A pending (not-yet-activated) subscription has nothing to reconcile.
func TestPollSubsSkipsPending(t *testing.T) {
	settled := false
	h := &Handler{
		idem:      idempotency.New(idempotency.NewMemStore()),
		settleRPC: func(_ context.Context, _ string, _ map[string]any) error { settled = true; return nil },
		listSubs: func(_ context.Context) ([]pendingSub, error) {
			return []pendingSub{{ID: 2, Provider: "stripe", ProviderSubID: "sub_x"}}, nil
		},
	}
	reg := registry.NewRegistryWith(map[string]payment.Client{
		"stripe": fakeGetSubscriber{sub: payment.Subscription{Status: payment.StatusPending}},
	})
	if err := h.pollSubsOnce(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if settled {
		t.Fatal("pending subscription must not settle")
	}
}

// A non-expired pending transaction must NOT be settled — keep polling.
func TestPollSkipsNonExpiredPending(t *testing.T) {
	var settled []string
	future := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
	h := &Handler{
		idem: idempotency.New(idempotency.NewMemStore()),
		settleRPC: func(_ context.Context, _ string, args map[string]any) error {
			settled = append(settled, fmt.Sprint(args["p_status"]))
			return nil
		},
		listPending: func(_ context.Context) ([]pendingTxn, error) {
			return []pendingTxn{{ID: 11, Provider: "payos", ExpireAt: future}}, nil
		},
	}
	reg := registry.NewRegistryWith(map[string]payment.Client{
		"payos": fakeGetCharger{st: payment.StatusPending},
	})
	if err := h.pollOnce(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(settled) != 0 {
		t.Fatalf("settled = %v, want []", settled)
	}
}
