package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/thinkonmay/global-proxy/api/config"
)

type httpServers struct {
	http  *http.Server
	https *http.Server
}

func (s *httpServers) shutdown(ctx context.Context) error {
	var errs []error
	if s.http != nil {
		errs = append(errs, s.http.Shutdown(ctx))
	}
	if s.https != nil {
		errs = append(errs, s.https.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

func startServers(cfg *config.Config, handler http.Handler) (*httpServers, <-chan error, error) {
	if cfg.TLS.Enabled {
		return startTLSServers(cfg, handler)
	}
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting HTTP server", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	return &httpServers{http: srv}, errCh, nil
}

func startTLSServers(cfg *config.Config, handler http.Handler) (*httpServers, <-chan error, error) {
	cacheDir := cfg.TLS.AutocertCache
	if cacheDir == "" {
		cacheDir = ".autocert_cache"
	}
	hosts := cfg.TLS.Hosts
	if len(hosts) == 0 {
		return nil, nil, fmt.Errorf("tls enabled but no hosts configured")
	}

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(hosts...),
	}

	httpsPort := cfg.TLS.HTTPSPort
	if httpsPort == "" {
		httpsPort = "443"
	}
	httpPort := cfg.TLS.HTTPPort
	if httpPort == "" {
		httpPort = "80"
	}

	httpsSrv := &http.Server{
		Addr:    ":" + httpsPort,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certManager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto, "h2", "http/1.1"},
		},
	}

	httpSrv := &http.Server{
		Addr:    ":" + httpPort,
		Handler: certManager.HTTPHandler(handler),
	}

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		slog.Info("starting HTTP server (ACME + redirect)", "port", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http :%s: %w", httpPort, err)
		}
	}()

	go func() {
		defer wg.Done()
		slog.Info("starting HTTPS server", "port", httpsPort, "hosts", hosts)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("https :%s: %w", httpsPort, err)
		}
	}()

	go func() {
		wg.Wait()
		close(errCh)
	}()

	return &httpServers{http: httpSrv, https: httpsSrv}, errCh, nil
}
