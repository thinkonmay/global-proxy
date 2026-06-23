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
	"github.com/thinkonmay/global-proxy/api/internal/gateway/adminhost"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/billing"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/catalog"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/files"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/gamification"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/grant"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/nodeproxy"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/noderuntime"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/ota"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/persona"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/pwa"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/store"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/volume"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/sse"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busnats "github.com/thinkonmay/global-proxy/api/pkg/bus/nats"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
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

	auth.ConfigureAuth(pr, cfg.PocketBase)

	eventBus, err := connectBus(cfg)
	if err != nil {
		return err
	}
	if eventBus != nil {
		defer func() { _ = eventBus.Close() }()
	}

	hub := sse.NewHub()
	if eventBus != nil {
		bus.Subscribe(eventBus, model.TopicSSE, "gateway-sse", hub.Dispatch)
	}

	h := handler.NewHandler(eventBus)

	var usageQ *usage.Querier
	if chConn, err := usage.OpenCH(cfg.ClickHouse); err != nil {
		if cfg.ClickHouse.Addr != "" {
			slog.Warn("clickhouse unavailable for usage reads", "err", err)
		}
	} else {
		defer func() { _ = chConn.Close() }()
		usageQ = usage.NewQuerier(chConn)
	}

	payReg := registry.NewRegistry(registry.ConfigFromGateway(cfg.Payment))
	payRates := payment.NewRateService(pr)

	catalogHTTP := catalog.New(pr)
	otaHTTP := ota.New(pr, cfg.PostgREST.ServiceKey)
	gamificationHTTP := gamification.New(pr, bt, usageQ)
	billingHTTP := billing.New(pr, bt, payReg, payRates)
	storeHTTP := store.New(pr, bt)
	grants := grant.New(*cfg, pr, bt)
	filesHTTP := files.New(*cfg, pr, bt)
	nodeProxy := nodeproxy.New(bt)
	personaHTTP := persona.New(pr, bt)
	nodeRuntimeHTTP := noderuntime.New(pr, cfg.PostgREST.ServiceKey)
	pwaHTTP := pwa.New(*cfg, pr, bt, personaHTTP)
	volumeHTTP := volume.New(pr, eventBus)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	coraza, err := initCoraza(cfg.WAF.Coraza)
	if err != nil {
		return err
	}

	gate, err := adminhost.InitGate(cfg)
	if err != nil {
		return fmt.Errorf("admin gate: %w", err)
	}
	if gate != nil {
		defer func() { _ = gate.Close() }()
	}

	mux := newMux(h, hub, catalogHTTP, otaHTTP, gamificationHTTP, billingHTTP, storeHTTP, grants, filesHTTP, nodeProxy, personaHTTP, nodeRuntimeHTTP, pwaHTTP, volumeHTTP, cfg, bt, coraza, gate, payReg, eventBus)

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
