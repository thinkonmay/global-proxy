package usage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type ActiveCluster struct {
	ID     int64
	Domain string
	Secret cluster.Secret
}

func LoadActiveClusters(ctx context.Context, pr *postgrest.Client) ([]ActiveCluster, error) {
	type row struct {
		ID     int64           `json:"id"`
		Domain string          `json:"domain"`
		Secret json.RawMessage `json:"secret"`
		Active *bool           `json:"active"`
	}
	var rows []row
	q := url.Values{}
	q.Set("select", "id,domain,secret,active")
	q.Set("active", "eq.true")
	if err := pr.Select(ctx, "clusters", q, &rows); err != nil {
		return nil, err
	}
	out := make([]ActiveCluster, 0, len(rows))
	for _, row := range rows {
		if row.ID == 4 {
			continue
		}
		sec, err := cluster.ParseSecret(row.Secret)
		if err != nil || sec.URL == "" {
			continue
		}
		out = append(out, ActiveCluster{ID: row.ID, Domain: row.Domain, Secret: sec})
	}
	return out, nil
}

func (c *Collector) tickAddons(ctx context.Context, now time.Time, bucket int64) addonStats {
	stats := addonStats{}
	dedupTTL := c.addonInterval*2 + time.Minute
	clusters, err := LoadActiveClusters(ctx, c.pr)
	if err != nil {
		c.log.Warn("addon tick: load clusters", "err", err)
		stats.errors++
		return stats
	}
	for _, cl := range clusters {
		pb := pocketbase.New(pocketbase.Config{
			URL:      cl.Secret.URL,
			Username: cl.Secret.Username,
			Password: cl.Secret.Password,
		})
		if err := c.scrapeAppAccess(ctx, pb, cl, now, bucket, dedupTTL, &stats); err != nil {
			c.log.Warn("addon tick: app_access", "cluster", cl.Domain, "err", err)
			stats.errors++
		}
		if err := c.scrapeBuckets(ctx, pb, cl, now, bucket, dedupTTL, &stats); err != nil {
			c.log.Warn("addon tick: buckets", "cluster", cl.Domain, "err", err)
			stats.errors++
		}
		if err := c.scrapeLLM(ctx, pb, cl, now, bucket, dedupTTL, &stats); err != nil {
			c.log.Warn("addon tick: llm", "cluster", cl.Domain, "err", err)
			stats.errors++
		}
	}
	return stats
}

type addonStats struct {
	appRows, bucketRows, llmRows int
	billed                       int
	events                       int
	skippedDedup                 int
	errors                       int
}

func (c *Collector) scrapeAppAccess(ctx context.Context, pb *pocketbase.Client, cl ActiveCluster, at time.Time, bucket int64, dedupTTL time.Duration, stats *addonStats) error {
	rows, err := cluster.ListAppAccessUsage(ctx, pb)
	if err != nil {
		return err
	}
	for _, row := range rows {
		stats.appRows++
		key := fmt.Sprintf("app:%s:%d", row.Email, bucket)
		ok, err := c.dedup.Claim(ctx, key, dedupTTL)
		if err != nil || !ok {
			stats.skippedDedup++
			continue
		}
		if !c.shadowMode {
			if err := c.pr.RPC(ctx, "sync_addon_app_access_usage", map[string]any{
				"p_email": row.Email, "p_usage": row.Usage,
			}, nil); err != nil {
				return err
			}
			stats.billed++
		}
		stats.events++
		_ = busPublish(ctx, c, model.UsageMsg{
			EventTime: at, UserEmail: row.Email, Metric: "app_access.units",
			Value: float64(row.Usage), Cluster: cl.Domain,
			TickBucket: uint64(bucket), Source: "collector",
		})
	}
	return nil
}

func (c *Collector) scrapeBuckets(ctx context.Context, pb *pocketbase.Client, cl ActiveCluster, at time.Time, bucket int64, dedupTTL time.Duration, stats *addonStats) error {
	rows, err := cluster.ListBucketUsage(ctx, pb)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.SizeMB <= 0 {
			continue
		}
		stats.bucketRows++
		key := fmt.Sprintf("bucket:%s:%s:%d", row.Email, row.BucketName, bucket)
		ok, err := c.dedup.Claim(ctx, key, dedupTTL)
		if err != nil || !ok {
			stats.skippedDedup++
			continue
		}
		if !c.shadowMode {
			if err := c.pr.RPC(ctx, "increment_addon_bucket_usage", map[string]any{
				"p_email": row.Email, "p_size_mb": row.SizeMB,
			}, nil); err != nil {
				return err
			}
			stats.billed++
		}
		stats.events++
		_ = busPublish(ctx, c, model.UsageMsg{
			EventTime: at, UserEmail: row.Email, SessionID: row.BucketName,
			Metric: "bucket.mb", Value: float64(row.SizeMB), Cluster: cl.Domain,
			TickBucket: uint64(bucket), Source: "collector",
		})
	}
	return nil
}

func (c *Collector) scrapeLLM(ctx context.Context, pb *pocketbase.Client, cl ActiveCluster, at time.Time, bucket int64, dedupTTL time.Duration, stats *addonStats) error {
	rows, err := cluster.ListLLMUsage(ctx, pb)
	if err != nil {
		return err
	}
	for _, row := range rows {
		stats.llmRows++
		key := fmt.Sprintf("llm:%s:%d", row.Email, bucket)
		ok, err := c.dedup.Claim(ctx, key, dedupTTL)
		if err != nil || !ok {
			stats.skippedDedup++
			continue
		}
		if !c.shadowMode {
			if err := c.pr.RPC(ctx, "sync_addon_llm_usage", map[string]any{
				"p_email": row.Email, "p_usage": row.Usage,
			}, nil); err != nil {
				return err
			}
			stats.billed++
		}
		stats.events++
		_ = busPublish(ctx, c, model.UsageMsg{
			EventTime: at, UserEmail: row.Email, Metric: "llm.units",
			Value: float64(row.Usage), Cluster: cl.Domain,
			TickBucket: uint64(bucket), Source: "collector",
		})
	}
	return nil
}

func busPublish(ctx context.Context, c *Collector, msg model.UsageMsg) error {
	return bus.Publish(ctx, c.bus, model.TopicUsage, msg)
}
