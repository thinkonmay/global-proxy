package handler

import (
	"context"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const (
	usageInsert = "INSERT INTO usage_events (event_time, user_email, session_id, metric, value, cluster)"
)

// handleUsage batch-inserts usage events into ClickHouse. The bus buffers by
// size/time, so one call == one INSERT (all-or-nothing): an error leaves the
// batch un-acked for redelivery, which ReplacingMergeTree dedups.
func (h *Handler) handleUsage(ctx context.Context, events []model.UsageMsg) []error {
	batch, err := h.ch.PrepareBatch(ctx, usageInsert)
	if err != nil {
		return bus.Each(len(events), err)
	}
	for _, e := range events {
		if err := batch.Append(e.EventTime, e.UserEmail, e.SessionID, e.Metric, e.Value, e.Cluster); err != nil {
			return bus.Each(len(events), err)
		}
	}
	return bus.Each(len(events), batch.Send())
}
