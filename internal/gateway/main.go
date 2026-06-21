package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busnats "github.com/thinkonmay/global-proxy/api/pkg/bus/nats"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	"github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func main() {
	if err := Run(); err != nil {
		log.Fatal(err)
	}
}

func Run() error {
	cfg, err := config.NewConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.SetupLogger()

	bt := guard.New(nil, guard.Config{MaxFailures: 5, Cooldown: 30 * time.Second, MaxConcurrent: 64})

	pr := postgrest.New(postgrest.Config{
		URL:        cfg.PostgREST.URL,
		AnonKey:    cfg.PostgREST.AnonKey,
		ServiceKey: cfg.PostgREST.ServiceKey,
		Transport:  bt,
	})

	eventBus, err := connectBus(cfg)
	if err != nil {
		return err
	}
	if eventBus != nil {
		defer func() { _ = eventBus.Close() }()
	}

	hub := NewSSEHub()
	if eventBus != nil {
		bus.Subscribe(eventBus, model.TopicSSE, "gateway-sse", hub.Dispatch)
	}

	h := handler.NewHandler(eventBus)
	devJobs := os.Getenv("APP_DEV_JOBS") == "1"

	var usageQ *usage.Querier
	if chConn, err := usage.OpenCH(cfg.ClickHouse); err != nil {
		if cfg.ClickHouse.Addr != "" {
			slog.Warn("clickhouse unavailable for usage reads", "err", err)
		}
	} else {
		defer func() { _ = chConn.Close() }()
		usageQ = usage.NewQuerier(chConn)
	}

	paySvc := payment.NewService(pr, payment.Config{
		Providers: payment.ConfigFromGateway(cfg.Payment),
	}, slog.Default())

	catalogHTTP := handler.NewCatalogHandler(pr)
	otaHTTP := handler.NewOTAHandler(pr)
	gamificationHTTP := handler.NewGamificationHandler(pr, bt, usageQ)
	billingHTTP := handler.NewBillingHandler(pr, bt, paySvc)
	storeHTTP := handler.NewStoreHandler(pr, bt)
	grants := handler.NewGrantHandler(*cfg, pr, bt)
	filesHTTP := handler.NewFilesHandler(*cfg, pr, bt)
	nodeProxy := handler.NewNodeProxyHandler(bt)
	personaHTTP := handler.NewPersonaHandler(pr, bt)
	nodeRuntimeHTTP := handler.NewNodeRuntimeHandler(pr, cfg.PostgREST.ServiceKey)
	pwa := handler.NewPWAHandler(*cfg, pr, bt, personaHTTP)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	coraza, err := initCoraza(cfg.WAF.Coraza)
	if err != nil {
		return err
	}

	gate, err := initAdminGate(cfg)
	if err != nil {
		return fmt.Errorf("admin gate: %w", err)
	}
	if gate != nil {
		defer func() { _ = gate.Close() }()
	}

	mux := newMux(h, hub, catalogHTTP, otaHTTP, gamificationHTTP, billingHTTP, storeHTTP, grants, filesHTTP, nodeProxy, personaHTTP, nodeRuntimeHTTP, pwa, devJobs, cfg, bt, coraza, gate)

	metricsCache, metricsSrv, metricsErrCh, err := startMetricsServer(cfg)
	if err != nil {
		return err
	}
	if metricsCache != nil {
		defer func() { _ = metricsCache.Close() }()
	}

	servers, errCh, err := startServers(cfg, mux)
	if err != nil {
		return err
	}
	servers.metrics = metricsSrv

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	case err := <-metricsErrCh:
		if err != nil {
			return fmt.Errorf("metrics server: %w", err)
		}
	case <-ctx.Done():
		slog.Info("shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return servers.shutdown(shutdownCtx)
	}
	return nil
}

func connectBus(cfg *config.Config) (bus.Client, error) {
	eventBus, err := busnats.New([]string{cfg.Nats.URL}, slog.Default())
	if err != nil {
		if cfg.Nats.Optional || os.Getenv("APP_NATS_OPTIONAL") == "1" {
			slog.Warn("nats unavailable, continuing without bus", "err", err)
			return nil, nil
		}
		return nil, fmt.Errorf("connect nats bus: %w", err)
	}
	return eventBus, nil
}
