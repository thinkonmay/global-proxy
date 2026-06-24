// Command worker consumes jobs off the bus and runs them. The heavy logic lives
// in the command handlers; everything else is just subscribe → run → record.
package main

import (
	"context"
	"log"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/gateway/repo"
	"github.com/thinkonmay/global-proxy/api/pkg/pg"

	busredis "github.com/thinkonmay/global-proxy/api/pkg/bus/redis"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.SetupLogger()

	pool, err := pg.New(pg.Options{
		Url:             cfg.Postgres.URL,
		Host:            cfg.Postgres.Host,
		Port:            cfg.Postgres.Port,
		Username:        cfg.Postgres.Username,
		Password:        cfg.Postgres.Password,
		Database:        cfg.Postgres.Database,
		MaxConnections:  10,
		MaxConnIdleTime: 5 * time.Minute,
	})
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()

	eventBus, err := busredis.Connect([]string{cfg.Redis.Addr}, slog.Default())
	if err != nil {
		log.Fatalf("connect redis bus: %v", err)
	}
	defer func() { _ = eventBus.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	repo := repo.NewRepo(pool)
	handler := &Handler{repo: repo, eventBus: eventBus}
	handler.Route()

	slog.Info("worker started")
	<-ctx.Done()
	slog.Info("worker stopped")
}
