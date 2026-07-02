package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
)

// pollGrace keeps recently-expired requests in the poll set for one extra
// window so a payment that settled just before expire_at (but whose webhook was
// missed) still gets captured, and abandoned ones get a terminal 'failed'.
const pollGrace = 15 * time.Minute

// failExpireGrace delays the local-clock "failed" inference past expire_at. Within
// this window the poller keeps trusting the provider's live status (GetCharge), so a
// payment the provider records slightly after the link expiry (bank/QR settle lag) is
// still captured as success instead of being force-failed by our clock — which would
// be dropped by settle_request's terminal guard when the late webhook arrives.
// Must stay below pollGrace so a now-failable request is still inside the listing window.
const failExpireGrace = 10 * time.Minute

type pendingTxn struct {
	ID         int64           `json:"id"`
	Provider   string          `json:"provider"`
	ChargeData json.RawMessage `json:"charge_data"`
	ExpireAt   string          `json:"expire_at"`
}

func idStr(id int64) string { return strconv.FormatInt(id, 10) }

// chargeID returns the provider-side charge id stored in charge_data at checkout time.
// The poll must use this (not the DB row id) because for some providers the lookup
// key differs: payos = txn id, payermax = "P"+txn id, stripe = cs_ session id.
func (t pendingTxn) chargeID() string {
	if len(t.ChargeData) == 0 {
		return ""
	}
	var d struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(t.ChargeData, &d) != nil {
		return ""
	}
	return d.ID
}

// failExpired reports whether the request is past expire_at by more than
// failExpireGrace — old enough to force a local 'failed' when the provider still
// won't return a terminal status. Within failExpireGrace of expiry it returns false
// so the poller keeps trusting GetCharge (absorbing provider settle lag).
func (t pendingTxn) failExpired(now time.Time) bool {
	if t.ExpireAt == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, t.ExpireAt)
	if err != nil {
		return false
	}
	return now.After(exp.Add(failExpireGrace))
}

func (h *Handler) defaultListPending(ctx context.Context) ([]pendingTxn, error) {
	var rows []pendingTxn
	q := url.Values{}
	q.Set("select", "id,provider,charge_data,expire_at")
	q.Set("status", "in.(pending,processing)")
	// Include rows up to pollGrace past expiry so late payments are captured
	// and abandoned ones can be failed, instead of vanishing at expire_at.
	q.Set("expire_at", "gt."+time.Now().UTC().Add(-pollGrace).Format(time.RFC3339))
	q.Set("limit", "50")
	if err := h.pr.SelectService(ctx, "requests", q, &rows); err != nil {
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
	now := time.Now().UTC()
	for _, t := range txns {
		client, ok := reg.Get(t.Provider)
		if !ok {
			slog.Warn("payment poll: unknown provider", "id", t.ID, "provider", t.Provider)
			continue
		}

		lookup := t.chargeID()
		if lookup == "" {
			lookup = idStr(t.ID)
		}

		// Resolve a terminal status: provider says terminal, or the request has
		// expired (within grace) and the provider has nothing better → failed.
		st := ""
		if ch, err := client.GetCharge(ctx, lookup); err != nil {
			slog.Warn("payment poll: getcharge", "id", t.ID, "err", err)
		} else if s := string(ch.Status); s == "success" || s == "cancelled" || s == "failed" {
			st = s
		}
		if st == "" {
			if t.failExpired(now) {
				st = "failed"
			} else {
				continue
			}
		}

		key := fmt.Sprintf("settle:%s:%d:%s", t.Provider, t.ID, st)
		if err := h.idem.Run(ctx, key, func(ctx context.Context) error {
			if err := h.settleRPC(ctx, "settle_request", map[string]any{"p_id": t.ID, "p_status": st}); err != nil {
				return err
			}
			h.notifyDepositSettled(ctx, idStr(t.ID), st)
			return nil
		}); err != nil {
			slog.Warn("payment poll: settle", "id", t.ID, "err", err)
		}
	}
	return nil
}

// StartPoller reconciles payment requests on a ticker until ctx is cancelled.
// It is the safety net behind webhooks: webhooks settle in real time, this
// catches anything the provider failed to deliver.
func (h *Handler) StartPoller(ctx context.Context, reg *registry.Registry, every time.Duration) {
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		h.pollTick(ctx, reg)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.pollTick(ctx, reg)
			}
		}
	}()
}

// pollTick runs one request reconcile pass.
func (h *Handler) pollTick(ctx context.Context, reg *registry.Registry) {
	if err := h.pollOnce(ctx, reg); err != nil {
		slog.Warn("payment poll tick", "err", err)
	}
}
