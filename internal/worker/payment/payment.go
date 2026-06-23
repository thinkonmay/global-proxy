// Package payment settles payment transactions off the bus and via a polling
// fallback, and persists saved cards. Settlement is idempotent so redeliveries
// and poll/event races dedup on (provider, txn, status).
package payment

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem        *idempotency.Guard
	pr          *postgrest.Client
	settleRPC   func(ctx context.Context, fn string, args map[string]any) error
	listPending func(ctx context.Context) ([]pendingTxn, error)
	saveCard    func(ctx context.Context, ev model.PaymentMsg) error
}

func New(idem *idempotency.Guard, pr *postgrest.Client) *Handler {
	h := &Handler{idem: idem, pr: pr}
	h.settleRPC = func(ctx context.Context, fn string, args map[string]any) error {
		return pr.RPC(ctx, fn, args, nil)
	}
	h.saveCard = func(ctx context.Context, ev model.PaymentMsg) error {
		return h.persistCard(ctx, ev)
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

// handlePaymentEvent settles a transaction idempotently and, for successful
// card-token events, persists the saved card. Both side-effects run inside the
// same idempotency guard so a redelivery dedups both. Card-save errors are
// logged and suppressed — they must not nak the settle.
// Dedup key is provider + txn id + status.
func (h *Handler) handlePaymentEvent(ctx context.Context, ev model.PaymentMsg) error {
	if ev.RefID == "" {
		return fmt.Errorf("payment event missing txn id (charge %s)", ev.ProviderID)
	}
	key := fmt.Sprintf("settle:%s:%s:%s", ev.Provider, ev.RefID, ev.Status)
	return h.idem.Run(ctx, key, func(ctx context.Context) error {
		if err := h.settleRPC(ctx, "settle_transaction", map[string]any{
			"p_id":     ev.RefID,
			"p_status": ev.Status,
		}); err != nil {
			return err
		}
		if ev.Status == "success" && ev.Token != "" {
			if err := h.saveCard(ctx, ev); err != nil {
				slog.Warn("payment: save card failed (best-effort)", "txn", ev.RefID, "err", err)
			}
		}
		return nil
	})
}

// persistCard looks up the transaction's user_id and upserts a card
// row. A duplicate-key (conflict) error is treated as success — the card is
// already stored. A user_id lookup miss inserts with a null user_id.
func (h *Handler) persistCard(ctx context.Context, ev model.PaymentMsg) error {
	// Look up user_id for this transaction.
	var rows []struct {
		UserID int64 `json:"user_id"`
	}
	q := url.Values{}
	q.Set("select", "user_id")
	q.Set("id", fmt.Sprintf("eq.%s", ev.RefID))
	q.Set("limit", "1")
	_ = h.pr.SelectService(ctx, "transactions", q, &rows) // lookup miss → proceed with null user_id

	body := map[string]any{
		"provider":     ev.Provider,
		"customer_ref": ev.CustomerRef,
		"pm_ref":       ev.Token,
		"brand":        ev.Brand,
		"last4":        ev.Last4,
	}
	if len(rows) > 0 && rows[0].UserID != 0 {
		body["user_id"] = rows[0].UserID
	}

	if err := h.pr.Insert(ctx, "card", body, nil); err != nil {
		if postgrest.IsConflict(err) {
			slog.Debug("payment: card already stored, skipping duplicate insert", "txn", ev.RefID)
			return nil
		}
		return fmt.Errorf("persist card for txn %s: %w", ev.RefID, err)
	}
	return nil
}
