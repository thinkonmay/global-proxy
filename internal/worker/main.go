// Command worker consumes jobs and usage events off the bus. Volume jobs use
// at-least-once delivery with idempotency; usage batches insert into ClickHouse.
package main

import (
	"context"
	"log"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/worker/handler"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"

	busnats "github.com/thinkonmay/global-proxy/api/pkg/bus/nats"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.SetupLogger()

	outbound := guard.New(nil, guard.Config{
		MaxFailures:   5,
		Cooldown:      30 * time.Second,
		MaxConcurrent: 32,
	})

	pr := postgrest.New(postgrest.Config{
		URL:        cfg.PostgREST.URL,
		AnonKey:    cfg.PostgREST.AnonKey,
		ServiceKey: cfg.PostgREST.ServiceKey,
		Transport:  outbound,
	})

	pb := pocketbase.New(pocketbase.Config{
		URL:       cfg.PocketBase.URL,
		Username:  cfg.PocketBase.Username,
		Password:  cfg.PocketBase.Password,
		Transport: outbound,
		Timeout:   30 * time.Second,
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

	h := handler.New(idempotency.New(idempotency.NewPostgrestStore(pr)), eventBus, ch, pr, pb)
	h.Init()
	if err := h.StartUsageCollector(ctx, cfg, slog.Default()); err != nil {
		log.Fatalf("usage collector: %v", err)
	}
	if err := h.StartPersonaWorker(ctx, cfg, slog.Default()); err != nil {
		log.Fatalf("persona worker: %v", err)
	}

	if cfg.Payment.Enabled {
		every, err := time.ParseDuration(cfg.Payment.PollEvery)
		if err != nil {
			log.Fatalf("payment.pollEvery: %v", err)
		}
		pay := payment.NewService(pr, payment.Config{
			PollEvery: every,
			Providers: payment.ConfigFromGateway(cfg.Payment),
		}, slog.Default())
		pay.Run(ctx)
	}

	slog.Info("worker started")
	<-ctx.Done()
	slog.Info("worker stopped")
}
