// Command worker consumes jobs and usage events off the bus: it runs each job
// at most once and batch-inserts usage into ClickHouse. The heavy logic lives in
// the command handlers; everything else is just subscribe → run → record.
package main

import (
	"context"
	"log"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/worker/handler"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"

	busnats "github.com/thinkonmay/global-proxy/api/pkg/bus/nats"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.SetupLogger()

	pr := postgrest.New(postgrest.Config{
		URL:        cfg.PostgREST.URL,
		AnonKey:    cfg.PostgREST.AnonKey,
		ServiceKey: cfg.PostgREST.ServiceKey,
	})

	ch, err := clickhouse.Open(&clickhouse.Options{
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
	defer func() { _ = ch.Close() }()

	eventBus, err := busnats.New([]string{cfg.Nats.URL}, slog.Default())
	if err != nil {
		log.Fatalf("connect nats bus: %v", err)
	}
	defer func() { _ = eventBus.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	h := handler.New(idempotency.New(idempotency.NewPostgrestStore(pr)), eventBus, ch, pr)
	h.Init()

	slog.Info("worker started")
	<-ctx.Done()
	slog.Info("worker stopped")
}
