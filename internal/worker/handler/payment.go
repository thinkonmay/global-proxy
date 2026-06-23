package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// handlePaymentEvent settles a transaction idempotently and, for successful
// card-token events, persists the saved card. Both side-effects run inside the
// same idempotency guard so a redelivery dedups both. Card-save errors are
// logged and suppressed — they must not nak the settle.
// Dedup key is provider + txn id + status.
func (h *Handler) handlePaymentEvent(ctx context.Context, ev model.PaymentEvent) error {
	if ev.TxnID == 0 {
		return fmt.Errorf("payment event missing txn id (charge %s)", ev.ChargeID)
	}
	key := fmt.Sprintf("settle:%s:%d:%s", ev.Provider, ev.TxnID, ev.Status)
	return h.idem.Run(ctx, key, func(ctx context.Context) error {
		if err := h.settleRPC(ctx, "settle_transaction", map[string]any{
			"p_id":     ev.TxnID,
			"p_status": ev.Status,
		}); err != nil {
			return err
		}
		if ev.Status == "success" && ev.Token != "" {
			if err := h.saveCard(ctx, ev); err != nil {
				slog.Warn("payment: save card failed (best-effort)", "txn", ev.TxnID, "err", err)
			}
		}
		return nil
	})
}

// persistCard looks up the transaction's user_id and upserts a payment_methods
// row. A duplicate-key (conflict) error is treated as success — the card is
// already stored. A user_id lookup miss inserts with a null user_id.
func (h *Handler) persistCard(ctx context.Context, ev model.PaymentEvent) error {
	// Look up user_id for this transaction.
	var rows []struct {
		UserID int64 `json:"user_id"`
	}
	q := url.Values{}
	q.Set("select", "user_id")
	q.Set("id", fmt.Sprintf("eq.%d", ev.TxnID))
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

	if err := h.pr.Insert(ctx, "payment_methods", body, nil); err != nil {
		if postgrest.IsConflict(err) {
			slog.Debug("payment: card already stored, skipping duplicate insert", "txn", ev.TxnID)
			return nil
		}
		return fmt.Errorf("persist card for txn %d: %w", ev.TxnID, err)
	}
	return nil
}
