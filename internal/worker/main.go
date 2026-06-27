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
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"

	busnats "github.com/thinkonmay/global-proxy/api/pkg/bus/nats"
	"github.com/thinkonmay/global-proxy/api/pkg/daemonclient"
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

	var dc *daemonclient.Client
	if cfg.Runtime.Grpc.Enabled || cfg.Runtime.Grpc.VaultPassword != "" {
		if cfg.Upstreams.Vault == "" {
			slog.Warn("worker daemon gRPC disabled: upstreams.vault not configured")
		} else {
			client, err := daemonclient.New(context.Background(), daemonclient.Config{
				VaultURL:         cfg.Upstreams.Vault,
				VaultPassword:    cfg.Runtime.Grpc.VaultPassword,
				VaultGatewayKey:  cfg.PostgREST.ServiceKey,
				ClientCN:         cfg.Runtime.Grpc.ClientCN,
				PKIMount:         cfg.Runtime.Grpc.PKIMount,
				PKIRole:          cfg.Runtime.Grpc.PKIRole,
				GrpcPort:         cfg.Runtime.Grpc.Port,
				HomeIssuerHost:   cfg.Runtime.Grpc.HomeIssuerHost,
				HomeGrpcOverride: cfg.Runtime.Grpc.HomeOverride,
			}, pr)
			if err != nil {
				log.Fatalf("daemon gRPC client: %v", err)
			}
			dc = client
			defer func() { _ = client.Close() }()
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	h := NewHandler(idempotency.New(idempotency.NewPostgrestStore(pr)), eventBus, ch, pr, dc)
	h.Init()
	h.StartJobPoller(ctx, slog.Default())
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
		payReg := registry.NewRegistry(registry.ConfigFromGateway(cfg.Payment))
		h.StartPaymentPoller(ctx, payReg, every)
	}

	slog.Info("worker started")
	<-ctx.Done()
	slog.Info("worker stopped")
}
