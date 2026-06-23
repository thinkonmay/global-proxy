// Package usage sinks usage events into ClickHouse and runs the in-process
// metering collector that publishes usage snapshots onto the bus.
package usage

import (
	"context"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const (
	usageInsert = "INSERT INTO usage_events (event_time, user_email, session_id, metric, value, cluster, node, volume_id, tick_bucket, source)"
)

type Handler struct {
	ch       driver.Conn
	pr       *postgrest.Client
	eventBus bus.Client
}

func New(ch driver.Conn, pr *postgrest.Client, eventBus bus.Client) *Handler {
	return &Handler{ch: ch, pr: pr, eventBus: eventBus}
}

// Init subscribes the handler to the usage topic as a batched ClickHouse sink.
func (h *Handler) Init(eventBus bus.Client) {
	bus.SubscribeBatch(
		eventBus,
		model.TopicUsage,
		"ch-usage-sink",
		h.handleUsage,
		bus.WithBatchSize(5000),
		bus.WithLinger(2*time.Second),
		bus.WithConcurrency(1),
		bus.WithDeliverNew(),
		bus.WithoutDLQ(),
	)
}

// handleUsage batch-inserts usage events into ClickHouse. The bus buffers by
// size/time, so one call == one INSERT (all-or-nothing): an error leaves the
// batch un-acked for redelivery, which ReplacingMergeTree dedups.
func (h *Handler) handleUsage(ctx context.Context, events []model.UsageMsg) []error {
	batch, err := h.ch.PrepareBatch(ctx, usageInsert)
	if err != nil {
		return bus.Each(len(events), err)
	}
	for _, e := range events {
		source := e.Source
		if source == "" {
			source = "collector"
		}
		if err := batch.Append(
			e.EventTime, e.UserEmail, e.SessionID, e.Metric, e.Value, e.Cluster,
			e.Node, e.VolumeID, e.TickBucket, source,
		); err != nil {
			return bus.Each(len(events), err)
		}
	}
	return bus.Each(len(events), batch.Send())
}
