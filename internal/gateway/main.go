package main

import (
	"context"
	"crypto/x509"
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
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/clusterrouting"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/files"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/gamification"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/grant"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/jobs"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/mail"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/metricsingest"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/noderuntime"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/ota"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/persona"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/pwa"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/runtime"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/store"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/vaultproxy"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/volume"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/sse"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busnats "github.com/thinkonmay/global-proxy/api/pkg/bus/nats"
	"github.com/thinkonmay/global-proxy/api/pkg/daemonclient"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
	"github.com/thinkonmay/global-proxy/api/pkg/vaultpki"
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

	auth.ConfigureAuth(pr, cfg.Runtime.Grpc.HomeIssuerHost, cfg.Supabase)

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
	storjClient := storj.TryOpen(cfg.Storj.AccessGrant)
	if storjClient != nil {
		defer storjClient.Close()
	}

	grantsHTTP := grant.New(pr, storjClient, bt)
	filesHTTP := files.New(*cfg, pr, bt)

	if cfg.Upstreams.Vault == "" {
		return fmt.Errorf("runtime gRPC requires upstreams.vault")
	}
	daemonGRPC, err := daemonclient.New(context.Background(), daemonclient.Config{
		VaultURL:           cfg.Upstreams.Vault,
		VaultPassword:      cfg.Runtime.Grpc.VaultPassword,
		VaultGatewayKey:    cfg.PostgREST.ServiceKey,
		ClientCN:           cfg.Runtime.Grpc.ClientCN,
		PKIMount:           cfg.Runtime.Grpc.PKIMount,
		PKIRole:            cfg.Runtime.Grpc.PKIRole,
		GrpcPort:           cfg.Runtime.Grpc.Port,
		HomeIssuerHost:     cfg.Runtime.Grpc.HomeIssuerHost,
		HomeGrpcOverride:   cfg.Runtime.Grpc.HomeOverride,
		HomeGrpcServerName: cfg.Runtime.Grpc.HomeServerName,
	}, pr)
	if err != nil {
		return fmt.Errorf("daemon gRPC client: %w", err)
	}
	defer func() { _ = daemonGRPC.Close() }()

	runtimeHTTP := runtime.New(runtime.Config{
		PublicURL: cfg.Gateway.PublicURL,
		Transport: bt,
		Daemon:    daemonGRPC,
		PostgREST: pr,
		Storj:     storjClient,
	})
	personaHTTP := persona.New(pr, bt)
	nodeRuntimeHTTP := noderuntime.New(pr, cfg.PostgREST.ServiceKey)
	vaultProxyHTTP := vaultproxy.New(cfg.Upstreams.Vault, cfg.PostgREST.ServiceKey, bt)
	pwaHTTP := pwa.New(*cfg, pr, bt, personaHTTP)
	jobsHTTP := jobs.New(pr, bt)
	volumeHTTP := volume.New(pr, eventBus)
	mailHTTP := mail.New(pr, eventBus, cfg.PostgREST.ServiceKey, bt)

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

	metricsStack, err := initMetricsStack(cfg)
	if err != nil {
		return err
	}
	if metricsStack != nil {
		defer func() { _ = metricsStack.cache.Close() }()
	}
	var metricsIngest *metricsingest.Handler
	if metricsStack != nil {
		metricsIngest = metricsingest.New(metricsStack.server, pr)
	}

	routingStore, err := initRoutingStore(cfg)
	if err != nil {
		return err
	}
	if routingStore != nil {
		defer func() { _ = routingStore.Close() }()
	}

	routingWatch := clusterrouting.NewWatchHub()
	routingHTTP := clusterrouting.New(routingStore, eventBus, routingWatch)
	routingHTTP.InitSubscriptions()

	mux := newMux(h, hub, catalogHTTP, otaHTTP, gamificationHTTP, billingHTTP, storeHTTP, grantsHTTP, filesHTTP, runtimeHTTP, personaHTTP, nodeRuntimeHTTP, vaultProxyHTTP, pwaHTTP, volumeHTTP, mailHTTP, jobsHTTP, metricsIngest, routingHTTP, cfg, bt, coraza, gate, payReg, eventBus)

	clientCAs, err := virtdaemonClientCAs(context.Background(), cfg)
	if err != nil {
		return err
	}

	servers, errCh, err := startServers(cfg, mux, clientCAs)
	if err != nil {
		return err
	}
	metricsSrv, metricsErrCh, err := startMetricsScrapeServer(cfg, metricsStack)
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

func virtdaemonClientCAs(ctx context.Context, cfg *config.Config) (*x509.CertPool, error) {
	if cfg.Upstreams.Vault == "" || cfg.Runtime.Grpc.VaultPassword == "" {
		slog.Warn("metrics mTLS client verification disabled: vault not configured")
		return nil, nil
	}
	pkiMount := cfg.Runtime.Grpc.PKIMount
	if pkiMount == "" {
		pkiMount = "pki"
	}
	pool, err := vaultpki.ClientCAPool(ctx, vaultpki.CARequest{
		Addr:       cfg.Upstreams.Vault,
		Username:   "virtdaemon",
		Password:   cfg.Runtime.Grpc.VaultPassword,
		PKIMount:   pkiMount,
		GatewayKey: cfg.PostgREST.ServiceKey,
	})
	if err != nil {
		return nil, fmt.Errorf("vault PKI CA for metrics mTLS: %w", err)
	}
	return pool, nil
}
