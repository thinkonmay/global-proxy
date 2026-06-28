package usage

import (
	"context"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const appUsageInsert = "INSERT INTO session_app_usage (event_time, user_email, runtime_session_id, app_key, duration_sec, launch_count, cluster, node, flush_reason, flush_seq, source)"

func (h *Handler) initAppUsageSink(eventBus bus.Client) {
	bus.SubscribeBatch(
		eventBus,
		model.TopicAppUsage,
		"ch-app-usage-sink",
		h.handleAppUsage,
		bus.WithBatchSize(5000),
		bus.WithLinger(2*time.Second),
		bus.WithConcurrency(1),
		bus.WithDeliverNew(),
		bus.WithoutDLQ(),
	)
}

func (h *Handler) handleAppUsage(ctx context.Context, events []model.AppUsageMsg) []error {
	batch, err := h.ch.PrepareBatch(ctx, appUsageInsert)
	if err != nil {
		return bus.Each(len(events), err)
	}
	for _, e := range events {
		source := e.Source
		if source == "" {
			source = "process_analytics"
		}
		launchCount := e.LaunchCount
		if launchCount == 0 {
			launchCount = 1
		}
		if err := batch.Append(
			e.EventTime, e.UserEmail, e.RuntimeSessionID, e.AppKey, e.DurationSec,
			launchCount, e.Cluster, e.Node, e.FlushReason, e.FlushSeq, source,
		); err != nil {
			return bus.Each(len(events), err)
		}
	}
	return bus.Each(len(events), batch.Send())
}
