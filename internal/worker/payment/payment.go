// Package payment settles payment requests off the bus and via a polling fallback.
// Settlement is idempotent so redeliveries and poll/event races dedup on
// (provider, request id, status).
package payment

import (
	"context"
	"fmt"
	"net/url"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem        *idempotency.Guard
	pr          *postgrest.Client
	eventBus    bus.Client
	settleRPC   func(ctx context.Context, fn string, args map[string]any) error
	listPending func(ctx context.Context) ([]pendingTxn, error)
	lookupEmail func(ctx context.Context, txnID string) string
}

// ssePaymentType tags a deposit-settled SSE event so the client can switch on it.
const ssePaymentType = "payment"

// paymentSSE is the SSEMsg.Data payload for a deposit settle: the client matches
// it by transaction id. Lives here (the producer), not in the generic SSE model.
type paymentSSE struct {
	TransactionID string `json:"transaction_id"`
	Status        string `json:"status"`
}

func New(idem *idempotency.Guard, pr *postgrest.Client) *Handler {
	h := &Handler{idem: idem, pr: pr}
	h.settleRPC = func(ctx context.Context, fn string, args map[string]any) error {
		return pr.RPC(ctx, fn, args, nil)
	}
	return h
}

// Init subscribes the handler to the payment-event topic and keeps the bus for
// publishing settle notifications (TopicSSE) the gateway fans out to clients.
func (h *Handler) Init(eventBus bus.Client) {
	h.eventBus = eventBus
	bus.Subscribe(
		eventBus,
		model.TopicPayment,
		"payment-settle",
		h.handlePaymentEvent,
		bus.WithConcurrency(8),
		bus.WithMaxDeliver(5),
	)
}

// notifyDepositSettled best-effort publishes a deposit's settled status to
// TopicSSE, routed to its owner; the gateway fans it out to that user's SSE
// stream so the client need not poll. Never fails the settle — a missed event
// falls back to the client's poll / initial-status read.
func (h *Handler) notifyDepositSettled(ctx context.Context, txnID, status string) {
	if h.eventBus == nil {
		return
	}
	lookup := h.lookupEmail
	if lookup == nil {
		lookup = h.depositOwnerEmail
	}
	email := lookup(ctx, txnID)
	if email == "" {
		return // can't route without the owner; client poll covers it
	}
	_ = model.PublishSSE(ctx, h.eventBus, model.SSEMsg[paymentSSE]{
		Type:      ssePaymentType,
		Recipient: email,
		Data:      paymentSSE{TransactionID: txnID, Status: status},
	})
}

// depositOwnerEmail resolves the transaction owner's email for SSE routing; ""
// on error or unknown row.
func (h *Handler) depositOwnerEmail(ctx context.Context, txnID string) string {
	var rows []struct {
		Email string `json:"email"`
	}
	q := url.Values{}
	q.Set("select", "email")
	q.Set("id", "eq."+txnID)
	q.Set("limit", "1")
	if err := h.pr.SelectService(ctx, "requests", q, &rows); err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0].Email
}

// handlePaymentEvent settles a charge event. Provider-recurring subscription
// events are no longer processed (provider subscriptions removed).
func (h *Handler) handlePaymentEvent(ctx context.Context, ev model.PaymentMsg) error {
	return h.settleCharge(ctx, ev)
}

// settleCharge settles a one-time payment request idempotently. The idempotency guard
// dedups redeliveries and poll/event races on provider + request id + status.
func (h *Handler) settleCharge(ctx context.Context, ev model.PaymentMsg) error {
	if ev.RefID == "" {
		return fmt.Errorf("payment event missing request id (charge %s)", ev.ProviderID)
	}
	key := fmt.Sprintf("settle:%s:%s:%s", ev.Provider, ev.RefID, ev.Status)
	return h.idem.Run(ctx, key, func(ctx context.Context) error {
		if err := h.settleRPC(ctx, "settle_request", map[string]any{
			"p_id":     ev.RefID,
			"p_status": ev.Status,
		}); err != nil {
			return err
		}
		h.notifyDepositSettled(ctx, ev.RefID, string(ev.Status))
		return nil
	})
}
