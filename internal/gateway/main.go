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
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
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
	globalRPC := handler.NewGlobalRPCHandler(*cfg, pr, bt)
	grants := handler.NewGrantHandler(*cfg, pr, bt)

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

	mux := newMux(h, hub, globalRPC, grants, devJobs, cfg, bt, coraza, gate)

	servers, errCh, err := startServers(cfg, mux)
	if err != nil {
		return err
	}

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
		slog.Info("shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return servers.shutdown(shutdownCtx)
	}
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
