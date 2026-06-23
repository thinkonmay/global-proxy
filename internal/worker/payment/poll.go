package payment

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
)

type pendingTxn struct {
	ID       int64  `json:"id"`
	Provider string `json:"provider"`
}

func idStr(id int64) string { return strconv.FormatInt(id, 10) }

func (h *Handler) defaultListPending(ctx context.Context) ([]pendingTxn, error) {
	var rows []pendingTxn
	q := url.Values{}
	q.Set("select", "id,provider")
	q.Set("status", "in.(pending,processing)")
	q.Set("expire_at", "gt."+time.Now().UTC().Format(time.RFC3339))
	q.Set("limit", "50")
	if err := h.pr.SelectService(ctx, "transactions", q, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (h *Handler) pollOnce(ctx context.Context, reg *registry.Registry) error {
	list := h.listPending
	if list == nil {
		list = h.defaultListPending
	}
	txns, err := list(ctx)
	if err != nil {
		return err
	}
	for _, t := range txns {
		client, ok := reg.Get(t.Provider)
		if !ok {
			continue
		}
		ch, err := client.GetCharge(ctx, idStr(t.ID))
		if err != nil {
			slog.Warn("payment poll: getcharge", "id", t.ID, "err", err)
			continue
		}
		st := string(ch.Status)
		if st != "success" && st != "cancelled" && st != "failed" {
			continue
		}
		key := fmt.Sprintf("settle:%s:%d:%s", t.Provider, t.ID, st)
		if err := h.idem.Run(ctx, key, func(ctx context.Context) error {
			return h.settleRPC(ctx, "settle_transaction", map[string]any{"p_id": t.ID, "p_status": st})
		}); err != nil {
			slog.Warn("payment poll: settle", "id", t.ID, "err", err)
		}
	}
	return nil
}

// StartPoller runs pollOnce on a ticker until ctx is cancelled.
func (h *Handler) StartPoller(ctx context.Context, reg *registry.Registry, every time.Duration) {
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		_ = h.pollOnce(ctx, reg)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := h.pollOnce(ctx, reg); err != nil {
					slog.Warn("payment poll tick", "err", err)
				}
			}
		}
	}()
}
