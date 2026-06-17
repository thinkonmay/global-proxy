package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/gateway/repo"
	"github.com/thinkonmay/global-proxy/api/pkg/pg"

	busredis "github.com/thinkonmay/global-proxy/api/pkg/bus/redis"
)

// Run loads config, wires the app, serves HTTP, and blocks until a signal
// triggers graceful shutdown.
func Run() error {
	cfg, err := config.NewConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
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
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()

	eventBus, err := busredis.Connect([]string{cfg.Redis.Addr}, slog.Default())
	if err != nil {
		return fmt.Errorf("connect redis bus: %w", err)
	}
	defer func() { _ = eventBus.Close() }()

	e := NewEcho()
	if err := SetupEcho(e, repo.NewRepo(pool), eventBus); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting HTTP server", "port", cfg.Port)
		if err := e.Start(":" + cfg.Port); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
		return e.Shutdown(shutdownCtx)
	}
}
