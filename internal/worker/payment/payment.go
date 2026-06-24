// Package payment settles payment transactions and subscription lifecycle events off the
// bus and via a polling fallback. Settlement is idempotent so redeliveries and poll/event
// races dedup — charges on (provider, txn, status), subscriptions on (sub id, status, period).
package payment

import (
	"context"
	"fmt"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem        *idempotency.Guard
	pr          *postgrest.Client
	settleRPC   func(ctx context.Context, fn string, args map[string]any) error
	listPending func(ctx context.Context) ([]pendingTxn, error)
}

func New(idem *idempotency.Guard, pr *postgrest.Client) *Handler {
	h := &Handler{idem: idem, pr: pr}
	h.settleRPC = func(ctx context.Context, fn string, args map[string]any) error {
		return pr.RPC(ctx, fn, args, nil)
	}
	return h
}

// Init subscribes the handler to the payment-event topic.
func (h *Handler) Init(eventBus bus.Client) {
	bus.Subscribe(
		eventBus,
		model.TopicPayment,
		"payment-settle",
		h.handlePaymentEvent,
		bus.WithConcurrency(8),
		bus.WithMaxDeliver(5),
	)
}

// handlePaymentEvent routes an event to the charge or subscription settle path by Kind.
func (h *Handler) handlePaymentEvent(ctx context.Context, ev model.PaymentMsg) error {
	switch ev.Kind {
	case payment.EventSubActivated, payment.EventSubRenewed, payment.EventSubCanceled:
		return h.settleSubscription(ctx, ev)
	default:
		return h.settleCharge(ctx, ev)
	}
}

// settleCharge settles a one-time transaction idempotently. The idempotency guard
// dedups redeliveries and poll/event races on provider + txn id + status.
func (h *Handler) settleCharge(ctx context.Context, ev model.PaymentMsg) error {
	if ev.RefID == "" {
		return fmt.Errorf("payment event missing txn id (charge %s)", ev.ProviderID)
	}
	key := fmt.Sprintf("settle:%s:%s:%s", ev.Provider, ev.RefID, ev.Status)
	return h.idem.Run(ctx, key, func(ctx context.Context) error {
		return h.settleRPC(ctx, "settle_transaction", map[string]any{
			"p_id":     ev.RefID,
			"p_status": ev.Status,
		})
	})
}

// settleSubscription applies a subscription lifecycle event idempotently. Activation carries
// RefID (local subscription-intent id) to link the provider subscription; renewals and cancels
// are keyed by provider subscription id. Dedup includes period end so each cycle settles once.
func (h *Handler) settleSubscription(ctx context.Context, ev model.PaymentMsg) error {
	if ev.ProviderSubID == "" {
		return fmt.Errorf("subscription event missing provider subscription id (ref %q)", ev.RefID)
	}
	key := fmt.Sprintf("settle_sub:%s:%s:%s:%d", ev.Provider, ev.ProviderSubID, ev.Status, ev.PeriodEnd)
	return h.idem.Run(ctx, key, func(ctx context.Context) error {
		args := map[string]any{
			"p_provider":        ev.Provider,
			"p_provider_sub_id": ev.ProviderSubID,
			"p_status":          ev.Status,
			"p_period_end":      ev.PeriodEnd,
		}
		if ev.RefID != "" {
			args["p_ref_id"] = ev.RefID
		}
		return h.settleRPC(ctx, "settle_subscription", args)
	})
}
