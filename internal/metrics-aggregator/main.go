package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.SetupLogger()

	if cfg.Metrics.IngestSecret == "" {
		log.Fatal("metrics ingest secret required (APP_METRICS_INGESTSECRET)")
	}

	cache, err := metricsagg.NewCacheWithOptions(metricsagg.CacheOptions{
		RedisURL:             cfg.Metrics.RedisURL,
		NodeTTLSeconds:       cfg.Metrics.CacheTTLSeconds,
		ScrapeCacheSeconds:   cfg.Metrics.ScrapeCacheSeconds,
	})
	if err != nil {
		log.Fatalf("redis cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	srv := metricsagg.NewServer(cache, cfg.Metrics.IngestSecret)
	httpSrv := &http.Server{
		Addr:              cfg.Metrics.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("metrics-aggregator listening", "addr", cfg.Metrics.ListenAddr, "redis", cfg.Metrics.RedisURL)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	slog.Info("metrics-aggregator stopped")
}
