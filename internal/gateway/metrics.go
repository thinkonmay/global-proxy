package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
)

// metricsStack holds the shared Redis cache and push/scrape handlers.
type metricsStack struct {
	cache  *metricsagg.Cache
	server *metricsagg.Server
}

// initMetricsStack wires the D16 Redis cache when metrics redis is configured.
func initMetricsStack(cfg *config.Config) (*metricsStack, error) {
	if cfg.Metrics.RedisURL == "" {
		return nil, nil
	}
	cache, err := metricsagg.NewCacheWithOptions(metricsagg.CacheOptions{
		RedisURL:           cfg.Metrics.RedisURL,
		NodeTTLSeconds:     cfg.Metrics.CacheTTLSeconds,
		ScrapeCacheSeconds: cfg.Metrics.ScrapeCacheSeconds,
	})
	if err != nil {
		return nil, fmt.Errorf("metrics cache: %w", err)
	}
	return &metricsStack{
		cache:  cache,
		server: metricsagg.NewServer(cache),
	}, nil
}

// startMetricsScrapeServer runs internal Prometheus scrape on :9090 (push uses gateway /v1/metrics/push).
func startMetricsScrapeServer(cfg *config.Config, stack *metricsStack) (*http.Server, <-chan error, error) {
	if stack == nil {
		return nil, nil, nil
	}
	httpSrv := &http.Server{
		Addr:              cfg.Metrics.ListenAddr,
		Handler:           stack.server.ScrapeHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("metrics scrape listening",
			"addr", cfg.Metrics.ListenAddr,
			"redis", cfg.Metrics.RedisURL,
		)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	return httpSrv, errCh, nil
}
