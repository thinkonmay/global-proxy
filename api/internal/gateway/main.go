package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler"
	busnats "github.com/thinkonmay/global-proxy/api/pkg/bus/nats"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
)

func main() {
	if err := Run(); err != nil {
		log.Fatal(err)
	}
}

// Run loads config, wires the app, serves HTTP, and blocks until a signal
// triggers graceful shutdown.
func Run() error {
	cfg, err := config.NewConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.SetupLogger()

	// Guard (breaker + bulkhead) for the /rest/v1 proxy, per host — fail fast,
	// never hang (TDD §2.1.1 / P11).
	bt := guard.New(nil, guard.Config{MaxFailures: 5, Cooldown: 30 * time.Second, MaxConcurrent: 64})

	eventBus, err := busnats.Connect([]string{cfg.Nats.URL}, slog.Default())
	if err != nil {
		return fmt.Errorf("connect nats bus: %w", err)
	}
	defer func() { _ = eventBus.Close() }()

	h := handler.NewHandler(eventBus)
	srv := &http.Server{Addr: ":" + cfg.Port, Handler: newMux(h, cfg.PostgREST, bt)}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting HTTP server", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
		slog.Info("shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
