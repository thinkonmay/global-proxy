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

// startMetricsServer runs the D16 push ingest + Prometheus scrape API inside the
// gateway process when metrics.ingestSecret is configured. Returns nil servers
// when metrics ingest is disabled.
func startMetricsServer(cfg *config.Config) (*metricsagg.Cache, *http.Server, <-chan error, error) {
	if cfg.Metrics.IngestSecret == "" {
		return nil, nil, nil, nil
	}

	cache, err := metricsagg.NewCacheWithOptions(metricsagg.CacheOptions{
		RedisURL:           cfg.Metrics.RedisURL,
		NodeTTLSeconds:     cfg.Metrics.CacheTTLSeconds,
		ScrapeCacheSeconds: cfg.Metrics.ScrapeCacheSeconds,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("metrics cache: %w", err)
	}

	srv := metricsagg.NewServer(cache, cfg.Metrics.IngestSecret)
	httpSrv := &http.Server{
		Addr:              cfg.Metrics.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("metrics ingest listening",
			"addr", cfg.Metrics.ListenAddr,
			"redis", cfg.Metrics.RedisURL,
		)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	return cache, httpSrv, errCh, nil
}
