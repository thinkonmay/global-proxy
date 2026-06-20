package usage

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

type VolumeOwner struct {
	Email     string
	ClusterID int64
}

type NodeCluster struct {
	ClusterID int64
	Domain    string
}

// Catalog caches PostgREST lookups for the usage collector tick.
type Catalog struct {
	pr *postgrest.Client

	mu          sync.RWMutex
	volumes     map[string]VolumeOwner
	nodes       map[string]NodeCluster
	clusters    map[int64]string
	loadedAt    time.Time
	ttl         time.Duration
}

func NewCatalog(pr *postgrest.Client, ttl time.Duration) *Catalog {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Catalog{pr: pr, ttl: ttl}
}

func (c *Catalog) VolumeOwner(ctx context.Context, volumeID string) (VolumeOwner, bool) {
	c.ensure(ctx)
	c.mu.RLock()
	defer c.mu.RUnlock()
	o, ok := c.volumes[strings.ToLower(strings.TrimSpace(volumeID))]
	return o, ok
}

func (c *Catalog) ClusterDomain(ctx context.Context, nodeHostname string) string {
	c.ensure(ctx)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if nc, ok := c.nodes[strings.TrimSpace(nodeHostname)]; ok {
		if d := c.clusters[nc.ClusterID]; d != "" {
			return d
		}
		return nc.Domain
	}
	return ""
}

func (c *Catalog) ensure(ctx context.Context) {
	c.mu.RLock()
	stale := time.Since(c.loadedAt) > c.ttl || c.volumes == nil
	c.mu.RUnlock()
	if !stale {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.loadedAt) <= c.ttl && c.volumes != nil {
		return
	}
	if err := c.reload(ctx); err != nil {
		// Keep stale cache on refresh failure.
		if c.volumes == nil {
			c.volumes = map[string]VolumeOwner{}
			c.nodes = map[string]NodeCluster{}
			c.clusters = map[int64]string{}
		}
	}
}

func (c *Catalog) reload(ctx context.Context) error {
	type userVolRow struct {
		Email     string `json:"email"`
		VolumeID  string `json:"volume_id"`
		ClusterID int64  `json:"cluster_id"`
	}
	var volRows []userVolRow
	q := url.Values{}
	q.Set("select", "email,volume_id,cluster_id")
	if err := c.pr.Select(ctx, "user_v2", q, &volRows); err != nil {
		return fmt.Errorf("user_v2: %w", err)
	}
	volumes := make(map[string]VolumeOwner, len(volRows))
	for _, row := range volRows {
		id := strings.ToLower(strings.TrimSpace(row.VolumeID))
		if id == "" || row.Email == "" {
			continue
		}
		volumes[id] = VolumeOwner{Email: row.Email, ClusterID: row.ClusterID}
	}

	type clusterRow struct {
		ID     int64  `json:"id"`
		Domain string `json:"domain"`
	}
	var clusterRows []clusterRow
	cq := url.Values{}
	cq.Set("select", "id,domain")
	cq.Set("active", "eq.true")
	if err := c.pr.Select(ctx, "clusters", cq, &clusterRows); err != nil {
		return fmt.Errorf("clusters: %w", err)
	}
	clusters := make(map[int64]string, len(clusterRows))
	for _, row := range clusterRows {
		clusters[row.ID] = strings.TrimSpace(row.Domain)
	}

	type nodeRow struct {
		Name      string `json:"name"`
		ClusterID int64  `json:"cluster_id"`
	}
	var nodeRows []nodeRow
	nq := url.Values{}
	nq.Set("select", "name,cluster_id")
	nq.Set("active", "eq.true")
	if err := c.pr.Select(ctx, "nodes", nq, &nodeRows); err != nil {
		return fmt.Errorf("nodes: %w", err)
	}
	nodes := make(map[string]NodeCluster, len(nodeRows))
	for _, row := range nodeRows {
		name := strings.TrimSpace(row.Name)
		if name == "" {
			continue
		}
		nodes[name] = NodeCluster{
			ClusterID: row.ClusterID,
			Domain:    clusters[row.ClusterID],
		}
	}

	c.volumes = volumes
	c.nodes = nodes
	c.clusters = clusters
	c.loadedAt = time.Now()
	return nil
}
