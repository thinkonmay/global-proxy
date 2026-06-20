package metricsagg

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	nodesIndexKey = "metrics:nodes"
	keyPrefix     = "metrics:node:"
)

type nodePayload struct {
	exporter []byte
	info     []byte
	expires  time.Time
}

// Cache is a two-tier store: in-memory L1 (per-node + merged scrape) over Redis L2.
type Cache struct {
	client *redis.Client
	ttl    time.Duration
	scrape time.Duration

	mu           sync.RWMutex
	l1           map[string]nodePayload
	merged       []byte
	mergedAt     time.Time
}

// CacheOptions configures Redis L2 and in-process L1 scrape cache.
type CacheOptions struct {
	RedisURL         string
	NodeTTLSeconds   int
	ScrapeCacheSeconds int
}

func NewCache(redisURL string, nodeTTLSeconds int) (*Cache, error) {
	return NewCacheWithOptions(CacheOptions{
		RedisURL:           redisURL,
		NodeTTLSeconds:     nodeTTLSeconds,
		ScrapeCacheSeconds: 10,
	})
}

func NewCacheWithOptions(opts CacheOptions) (*Cache, error) {
	opt, err := redis.ParseURL(opts.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	nodeTTL := time.Duration(opts.NodeTTLSeconds) * time.Second
	if nodeTTL <= 0 {
		nodeTTL = 90 * time.Second
	}
	scrapeTTL := time.Duration(opts.ScrapeCacheSeconds) * time.Second
	if scrapeTTL <= 0 {
		scrapeTTL = 10 * time.Second
	}
	return &Cache{
		client: client,
		ttl:    nodeTTL,
		scrape: scrapeTTL,
		l1:     make(map[string]nodePayload),
	}, nil
}

func (c *Cache) Close() error {
	return c.client.Close()
}

func nodeKey(node, suffix string) string {
	return keyPrefix + node + ":" + suffix
}

func (c *Cache) invalidateMergedLocked() {
	c.merged = nil
	c.mergedAt = time.Time{}
}

func (c *Cache) touchL1Locked(node, suffix string, body []byte) {
	entry := c.l1[node]
	switch suffix {
	case "exporter":
		entry.exporter = append([]byte(nil), body...)
	case "info":
		entry.info = append([]byte(nil), body...)
	}
	entry.expires = time.Now().Add(c.ttl)
	c.l1[node] = entry
	c.invalidateMergedLocked()
}

// SavePush writes through to Redis and refreshes the in-memory L1 entry.
func (c *Cache) SavePush(ctx context.Context, node, pushType string, body []byte) error {
	node = strings.TrimSpace(node)
	if node == "" {
		return fmt.Errorf("empty node")
	}
	suffix, err := pushSuffix(pushType)
	if err != nil {
		return err
	}
	key := nodeKey(node, suffix)
	pipe := c.client.Pipeline()
	pipe.Set(ctx, key, body, c.ttl)
	pipe.SAdd(ctx, nodesIndexKey, node)
	pipe.Expire(ctx, nodesIndexKey, c.ttl*2)
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}

	c.mu.Lock()
	c.touchL1Locked(node, suffix, body)
	c.mu.Unlock()
	return nil
}

func pushSuffix(pushType string) (string, error) {
	switch strings.TrimSpace(pushType) {
	case "node-exporter":
		return "exporter", nil
	case "info":
		return "info", nil
	default:
		return "", fmt.Errorf("unsupported push type %q", pushType)
	}
}

// NodeSnapshot is one worker node's cached exporter payload and freshness.
type NodeSnapshot struct {
	Node   string
	Body   []byte
	Stale  bool
}

// NodeInfoSnapshot is the latest WorkerInfor JSON push for one node.
type NodeInfoSnapshot struct {
	Node  string
	Info  []byte
	Stale bool
}

// ListNodeInfo returns cached WorkerInfor payloads for all known nodes.
func (c *Cache) ListNodeInfo(ctx context.Context) ([]NodeInfoSnapshot, error) {
	nodes, err := c.client.SMembers(ctx, nodesIndexKey).Result()
	if err != nil {
		return nil, err
	}
	c.mu.RLock()
	for node := range c.l1 {
		if !slices.Contains(nodes, node) {
			nodes = append(nodes, node)
		}
	}
	c.mu.RUnlock()
	if len(nodes) == 0 {
		return nil, nil
	}

	out := make([]NodeInfoSnapshot, 0, len(nodes))
	missing := make([]string, 0)

	c.mu.RLock()
	for _, node := range nodes {
		if entry, ok := c.l1[node]; ok && time.Now().Before(entry.expires) && len(entry.info) > 0 {
			out = append(out, NodeInfoSnapshot{Node: node, Info: append([]byte(nil), entry.info...)})
			continue
		}
		missing = append(missing, node)
	}
	c.mu.RUnlock()

	if len(missing) == 0 {
		return out, nil
	}
	pipe := c.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(missing))
	for i, node := range missing {
		cmds[i] = pipe.Get(ctx, nodeKey(node, "info"))
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, node := range missing {
		body, err := cmds[i].Bytes()
		if err == redis.Nil {
			out = append(out, NodeInfoSnapshot{Node: node, Stale: true})
			delete(c.l1, node)
			continue
		}
		if err != nil {
			return nil, err
		}
		c.touchL1Locked(node, "info", body)
		out = append(out, NodeInfoSnapshot{Node: node, Info: append([]byte(nil), body...)})
	}
	return out, nil
}

// MergedExposition is the full Prometheus text served on GET /metrics.
func (c *Cache) MergedExposition(ctx context.Context) ([]byte, error) {
	c.mu.RLock()
	if len(c.merged) > 0 && time.Since(c.mergedAt) < c.scrape {
		out := append([]byte(nil), c.merged...)
		c.mu.RUnlock()
		return out, nil
	}
	c.mu.RUnlock()

	snapshots, err := c.loadSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	body := buildExposition(snapshots)

	c.mu.Lock()
	c.merged = append([]byte(nil), body...)
	c.mergedAt = time.Now()
	c.mu.Unlock()
	return body, nil
}

func (c *Cache) loadSnapshots(ctx context.Context) ([]NodeSnapshot, error) {
	nodes, err := c.client.SMembers(ctx, nodesIndexKey).Result()
	if err != nil {
		return nil, err
	}
	c.mu.RLock()
	for node := range c.l1 {
		if !slices.Contains(nodes, node) {
			nodes = append(nodes, node)
		}
	}
	c.mu.RUnlock()
	if len(nodes) == 0 {
		return nil, nil
	}

	out := make([]NodeSnapshot, 0, len(nodes))
	missing := make([]string, 0)

	c.mu.RLock()
	for _, node := range nodes {
		if entry, ok := c.l1[node]; ok && time.Now().Before(entry.expires) && len(entry.exporter) > 0 {
			out = append(out, NodeSnapshot{Node: node, Body: entry.exporter})
			continue
		}
		missing = append(missing, node)
	}
	c.mu.RUnlock()

	if len(missing) > 0 {
		pipe := c.client.Pipeline()
		cmds := make([]*redis.StringCmd, len(missing))
		for i, node := range missing {
			cmds[i] = pipe.Get(ctx, nodeKey(node, "exporter"))
		}
		if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
			return nil, err
		}
		c.mu.Lock()
		for i, node := range missing {
			body, err := cmds[i].Bytes()
			if err == redis.Nil {
				out = append(out, NodeSnapshot{Node: node, Stale: true})
				delete(c.l1, node)
				continue
			}
			if err != nil {
				c.mu.Unlock()
				return nil, err
			}
			c.touchL1Locked(node, "exporter", body)
			out = append(out, NodeSnapshot{Node: node, Body: body})
		}
		c.mu.Unlock()
	}
	return out, nil
}
