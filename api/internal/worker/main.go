// Command worker consumes jobs off the bus and runs them. The heavy logic lives
// in the command handlers; everything else is just subscribe → run → record.
package main

import (
	"context"
	"log"
	"log/slog"
	"os/signal"
	"syscall"

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

	eventBus, err := busnats.Connect([]string{cfg.Nats.URL}, slog.Default())
	if err != nil {
		log.Fatalf("connect nats bus: %v", err)
	}
	defer func() { _ = eventBus.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	h := handler.New(idempotency.New(idempotency.NewPostgrestStore(pr)), eventBus)
	h.Init()

	slog.Info("worker started")
	<-ctx.Done()
	slog.Info("worker stopped")
}
