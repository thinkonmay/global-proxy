package daemonclient

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/audit"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/vaultpki"
	"github.com/thinkonmay/global-proxy/api/pkg/workerinfor"
	"google.golang.org/grpc"
)

const defaultInfoTimeout = 15 * time.Second

// Config configures gateway→cluster-master virtdaemon gRPC over mTLS.
type Config struct {
	VaultURL      string
	VaultPassword string
	VaultGatewayKey string
	ClientCN      string
	PKIMount      string
	PKIRole       string
	GrpcPort      int
	HomeIssuerHost   string
	HomeGrpcOverride string
	HomeGrpcServerName string
}

// Client calls persistent.Daemon Info over mTLS.
type Client struct {
	cfg Config
	pr  *postgrest.Client
	mtls *vaultpki.Reloadable
	stopRenew chan struct{}

	mu    sync.Mutex
	conns map[int64]*grpc.ClientConn
}

// New issues the gateway client cert and starts renewal when Vault is configured.
func New(ctx context.Context, cfg Config, pr *postgrest.Client) (*Client, error) {
	if cfg.VaultURL == "" || cfg.VaultPassword == "" {
		return nil, fmt.Errorf("daemon gRPC: vault url and password required")
	}
	if cfg.ClientCN == "" {
		cfg.ClientCN = "thinkmay-gateway"
	}
	if cfg.PKIMount == "" {
		cfg.PKIMount = "pki"
	}
	if cfg.PKIRole == "" {
		cfg.PKIRole = "virtdaemon"
	}
	c := &Client{
		cfg:       cfg,
		pr:        pr,
		mtls:      vaultpki.NewReloadable(),
		stopRenew: make(chan struct{}),
		conns:     map[int64]*grpc.ClientConn{},
	}
	mat, err := c.issue(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.mtls.Store(mat); err != nil {
		return nil, err
	}
	go c.renewLoop()
	slog.Info("daemon gRPC client mTLS enabled", "cn", cfg.ClientCN, "vault", cfg.VaultURL)
	return c, nil
}

func (c *Client) issue(ctx context.Context) (*vaultpki.Material, error) {
	return vaultpki.Issue(ctx, vaultpki.IssueRequest{
		Addr:       c.cfg.VaultURL,
		Username:   "virtdaemon",
		Password:   c.cfg.VaultPassword,
		PKIMount:   c.cfg.PKIMount,
		PKIRole:    c.cfg.PKIRole,
		CommonName: c.cfg.ClientCN,
		GatewayKey: c.cfg.VaultGatewayKey,
	})
}

func (c *Client) renewLoop() {
	for {
		mat := c.mtls.Material()
		if mat == nil {
			return
		}
		delay, err := vaultpki.RenewalDelay(mat)
		if err != nil {
			delay = vaultpki.ReissueRetryDelay()
		}
		select {
		case <-c.stopRenew:
			return
		case <-time.After(delay):
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		next, err := c.issue(ctx)
		cancel()
		if err != nil {
			slog.Warn("daemon gRPC cert renewal failed", "err", err)
			time.Sleep(vaultpki.ReissueRetryDelay())
			continue
		}
		if err := c.mtls.Store(next); err != nil {
			slog.Warn("daemon gRPC cert store failed", "err", err)
			continue
		}
		slog.Info("daemon gRPC client cert renewed", "cn", c.cfg.ClientCN)
	}
}

// Close shuts down renewal and gRPC connections.
func (c *Client) Close() error {
	close(c.stopRenew)
	c.mu.Lock()
	defer c.mu.Unlock()
	var first error
	for id, conn := range c.conns {
		if err := conn.Close(); err != nil && first == nil {
			first = err
		}
		delete(c.conns, id)
	}
	return first
}

// InfoForUser fans out Info() across clusters in user_v2 and merges filtered results (D30).
func (c *Client) InfoForUser(ctx context.Context, email string) (*persistent.WorkerInfor, error) {
	groups, err := cluster.UserVolumeGroups(ctx, c.pr, email)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return &persistent.WorkerInfor{}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, defaultInfoTimeout)
	defer cancel()

	var (
		parts []*persistent.WorkerInfor
		mu    sync.Mutex
		wg    sync.WaitGroup
	)
	for clusterID, vols := range groups {
		wg.Add(1)
		go func(clusterID int64, vols []string) {
			defer wg.Done()
			info, err := c.infoCluster(ctx, clusterID)
			if err != nil {
				slog.Warn("daemon Info failed for cluster", "cluster_id", clusterID, "err", err)
				return
			}
			filtered := workerinfor.Filter(info, vols)
			mu.Lock()
			parts = append(parts, filtered)
			mu.Unlock()
		}(clusterID, vols)
	}
	wg.Wait()
	return workerinfor.Merge(parts), nil
}

func (c *Client) infoCluster(ctx context.Context, clusterID int64) (*persistent.WorkerInfor, error) {
	conn, err := c.conn(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	return persistent.NewDaemonClient(conn).Info(audit.OutgoingGRPCMetadata(ctx), &persistent.Empty{})
}

func (c *Client) conn(ctx context.Context, clusterID int64) (*grpc.ClientConn, error) {
	c.mu.Lock()
	if conn, ok := c.conns[clusterID]; ok {
		c.mu.Unlock()
		return conn, nil
	}
	c.mu.Unlock()

	info, err := cluster.Lookup(ctx, c.pr, clusterID)
	if err != nil {
		return nil, err
	}
	target := cluster.GrpcTarget(info, c.cfg.GrpcPort, c.cfg.HomeIssuerHost, c.cfg.HomeGrpcOverride)
	if target == "" {
		return nil, fmt.Errorf("cluster %d: no gRPC target", clusterID)
	}
	serverName := ""
	if o := strings.TrimSpace(c.cfg.HomeGrpcOverride); o != "" {
		if c.cfg.HomeIssuerHost == "" ||
			strings.EqualFold(cluster.NormalizeHost(info.Domain), cluster.NormalizeHost(c.cfg.HomeIssuerHost)) {
			serverName = c.cfg.HomeGrpcServerName
		}
	}
	dialOpts, err := vaultpki.GrpcDialOptions(c.mtls, serverName)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.conns[clusterID]; ok {
		_ = conn.Close()
		return existing, nil
	}
	c.conns[clusterID] = conn
	return conn, nil
}
