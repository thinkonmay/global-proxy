// Command usagesink drains the usage.snapshot stream off the bus and batch-
// inserts into ClickHouse. The bus (SubscribeBatch) already buffers by size/time
// and acks only after the handler returns nil — so one handler call == one
// ClickHouse INSERT, at-least-once (ReplacingMergeTree dedups retries).
package main

import (
	"context"
	"log"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/shared/model"

	busnats "github.com/thinkonmay/global-proxy/api/pkg/bus/nats"
)

const (
	sinkGroup     = "ch-usage-sink"
	sinkBatchSize = 5000            // flush at this many rows
	sinkLinger    = 2 * time.Second // ...or this long after the first row
	insertStmt    = "INSERT INTO usage_events (event_time, user_email, session_id, metric, value, cluster)"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.SetupLogger()

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.ClickHouse.Addr},
		Auth: clickhouse.Auth{
			Database: cfg.ClickHouse.Database,
			Username: cfg.ClickHouse.Username,
			Password: cfg.ClickHouse.Password,
		},
	})
	if err != nil {
		log.Fatalf("clickhouse open: %v", err)
	}
	defer func() { _ = conn.Close() }()

	eventBus, err := busnats.Connect([]string{cfg.Nats.URL}, slog.Default())
	if err != nil {
		log.Fatalf("connect nats bus: %v", err)
	}
	defer func() { _ = eventBus.Close() }()

	bus.SubscribeBatch(eventBus, model.TopicUsage, sinkGroup,
		func(ctx context.Context, events []model.UsageEvent) []error {
			// One batched INSERT: all-or-nothing, so fan the result to every row.
			return bus.Each(len(events), insertBatch(ctx, conn, events))
		},
		bus.WithBatchSize(sinkBatchSize),
		bus.WithLinger(sinkLinger),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("usagesink started", "batch", sinkBatchSize, "linger", sinkLinger)
	<-ctx.Done()
	slog.Info("usagesink stopped")
}

// insertBatch sends one batch INSERT. A returned error leaves the batch un-acked
// on the bus, so it is redelivered (ReplacingMergeTree collapses the duplicate).
func insertBatch(ctx context.Context, conn driver.Conn, events []model.UsageEvent) error {
	batch, err := conn.PrepareBatch(ctx, insertStmt)
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := batch.Append(e.EventTime, e.UserEmail, e.SessionID, e.Metric, e.Value, e.Cluster); err != nil {
			return err
		}
	}
	return batch.Send()
}
