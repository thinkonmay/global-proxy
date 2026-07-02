package usage

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// Collector turns pushed WorkerInfor payloads into billing RPCs and analytics events.
type Collector struct {
	cache        *metricsagg.Cache
	catalog      *Catalog
	dedup        *Dedup
	pr           *postgrest.Client
	bus          bus.Client
	log          *slog.Logger
	tickInterval  time.Duration
	addonInterval time.Duration
	sessionMins   int
}

type Options struct {
	TickInterval  time.Duration
	AddonInterval time.Duration
	SessionMins   int
}

func NewCollector(
	cache *metricsagg.Cache,
	catalog *Catalog,
	dedup *Dedup,
	pr *postgrest.Client,
	eventBus bus.Client,
	log *slog.Logger,
	opts Options,
) *Collector {
	if log == nil {
		log = slog.Default()
	}
	interval := opts.TickInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	mins := opts.SessionMins
	if mins <= 0 {
		mins = 5
	}
	addonEvery := opts.AddonInterval
	if addonEvery <= 0 {
		addonEvery = time.Hour
	}
	return &Collector{
		cache:         cache,
		catalog:       catalog,
		dedup:         dedup,
		pr:            pr,
		bus:           eventBus,
		log:           log,
		tickInterval:  interval,
		addonInterval: addonEvery,
		sessionMins:   mins,
	}
}

// Run ticks until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	c.log.Info("usage collector started",
		"session_every", c.tickInterval,
		"addon_every", c.addonInterval,
		"session_minutes", c.sessionMins,
	)
	sessionTicker := time.NewTicker(c.tickInterval)
	addonTicker := time.NewTicker(c.addonInterval)
	defer sessionTicker.Stop()
	defer addonTicker.Stop()

	c.tickSession(ctx)
	c.tickAddon(ctx)
	for {
		select {
		case <-ctx.Done():
			c.log.Info("usage collector stopped")
			return
		case <-sessionTicker.C:
			c.tickSession(ctx)
		case <-addonTicker.C:
			c.tickAddon(ctx)
		}
	}
}

func (c *Collector) tickAddon(ctx context.Context) {
	now := time.Now().UTC()
	bucket := TickBucket(now.Unix(), int64(c.addonInterval.Seconds()))
	stats := c.tickAddons(ctx, now, bucket)
	c.log.Info("addon tick complete",
		"app_rows", stats.appRows,
		"bucket_rows", stats.bucketRows,
		"llm_rows", stats.llmRows,
		"billed", stats.billed,
		"events", stats.events,
		"skipped_dedup", stats.skippedDedup,
		"errors", stats.errors,
		"bucket", bucket,
	)
}

func (c *Collector) tickSession(ctx context.Context) {
	c.tick(ctx)
}

type tickStats struct {
	nodes         int
	staleNodes    int
	sessionTicks  int
	sessionBilled int
	volumeTicks   int
	volumeBilled  int
	events        int
	skippedDedup  int
	skippedOwner  int
	errors        int
}

func (c *Collector) tick(ctx context.Context) {
	stats := tickStats{}
	now := time.Now().UTC()
	bucket := TickBucket(now.Unix(), int64(c.tickInterval.Seconds()))
	dedupTTL := c.tickInterval*2 + time.Minute

	payloads, err := c.cache.ListNodeInfo(ctx)
	if err != nil {
		c.log.Error("usage tick: list node info", "err", err)
		return
	}
	stats.nodes = len(payloads)

	parsed := make([]WorkerInfo, 0, len(payloads))
	for _, p := range payloads {
		if p.Stale || len(p.Info) == 0 {
			stats.staleNodes++
			continue
		}
		info, err := ParseWorkerInfo(p.Info)
		if err != nil {
			c.log.Warn("usage tick: parse info", "node", p.Node, "err", err)
			stats.errors++
			continue
		}
		if info.Hostname == "" {
			info.Hostname = p.Node
		}
		parsed = append(parsed, info)

		for _, tick := range ExtractSessionTicks(info, p.Node) {
			stats.sessionTicks++
			owner, ok := c.catalog.VolumeOwner(ctx, tick.VolumeID)
			if !ok {
				stats.skippedOwner++
				continue
			}
			dedupKey := fmt.Sprintf("sess:%s:%s:%d", tick.SessionID, tick.VolumeID, bucket)
			claimed, err := c.dedup.Claim(ctx, dedupKey, dedupTTL)
			if err != nil {
				c.log.Warn("usage tick: dedup session", "err", err)
				stats.errors++
				continue
			}
			if !claimed {
				stats.skippedDedup++
				continue
			}
			cluster := c.catalog.ClusterDomain(ctx, p.Node)
			if cluster == "" && owner.ClusterID > 0 {
				cluster = fmt.Sprintf("cluster-%d", owner.ClusterID)
			}
			if err := c.applySessionUsage(ctx, owner.Email, cluster, tick, now, bucket, &stats); err != nil {
				c.log.Warn("usage tick: session", "email", owner.Email, "session", tick.SessionID, "err", err)
				stats.errors++
			}
		}
	}

	// Disk usage is priced per GB-hour (plan price.storage.per_quantity == 720,
	// i.e. hours/month), so total_data_credit must accrue at most one GB sample
	// per hour per volume. This loop runs on every session tick (5m), so bill the
	// volume on the hourly addon bucket instead of the session bucket: the dedup
	// claim then collapses the ~12 intra-hour session ticks into a single hourly
	// sample, keeping the accumulator in true GB-hours.
	volumeBucket := TickBucket(now.Unix(), int64(c.addonInterval.Seconds()))
	volumeDedupTTL := c.addonInterval*2 + time.Minute
	for _, vol := range ExtractVolumeTicks(parsed) {
		stats.volumeTicks++
		owner, ok := c.catalog.VolumeOwner(ctx, vol.VolumeID)
		if !ok {
			stats.skippedOwner++
			continue
		}
		if vol.SizeGB <= 0 {
			continue
		}
		dedupKey := fmt.Sprintf("vol:%s:%d", vol.VolumeID, volumeBucket)
		claimed, err := c.dedup.Claim(ctx, dedupKey, volumeDedupTTL)
		if err != nil {
			c.log.Warn("usage tick: dedup volume", "err", err)
			stats.errors++
			continue
		}
		if !claimed {
			stats.skippedDedup++
			continue
		}
		cluster := c.catalog.ClusterDomain(ctx, vol.Node)
		if err := c.applyVolumeUsage(ctx, owner.Email, cluster, vol, now, volumeBucket, &stats); err != nil {
			c.log.Warn("usage tick: volume", "email", owner.Email, "volume", vol.VolumeID, "err", err)
			stats.errors++
		}
	}

	c.log.Info("usage tick complete",
		"nodes", stats.nodes,
		"stale_nodes", stats.staleNodes,
		"session_ticks", stats.sessionTicks,
		"session_billed", stats.sessionBilled,
		"volume_ticks", stats.volumeTicks,
		"volume_billed", stats.volumeBilled,
		"analytics_events", stats.events,
		"skipped_dedup", stats.skippedDedup,
		"skipped_owner", stats.skippedOwner,
		"errors", stats.errors,
		"bucket", bucket,
	)
}

// resolveMachineIDByVolume looks up the machine id for the given volume_id.
// Returns "" if no active machine is found.
func (c *Collector) resolveMachineIDByVolume(ctx context.Context, volumeID string) string {
	var rows []struct {
		ID string `json:"id"`
	}
	q := url.Values{}
	q.Set("select", "id")
	q.Set("volume_id", "eq."+volumeID)
	q.Set("status", "eq.active")
	q.Set("order", "created_at.desc")
	q.Set("limit", "1")
	if err := c.pr.SelectService(ctx, "machines", q, &rows); err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0].ID
}

// resolveMachineIDByEmail looks up the most recently created active machine for
// the given user email. Returns "" if no active machine is found.
func (c *Collector) resolveMachineIDByEmail(ctx context.Context, email string) string {
	var rows []struct {
		ID string `json:"id"`
	}
	q := url.Values{}
	q.Set("select", "id")
	q.Set("user_email", "eq."+email)
	q.Set("status", "eq.active")
	q.Set("order", "created_at.desc")
	q.Set("limit", "1")
	if err := c.pr.SelectService(ctx, "machines", q, &rows); err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0].ID
}

func (c *Collector) applySessionUsage(ctx context.Context, email, cluster string, tick SessionTick, at time.Time, bucket int64, stats *tickStats) error {
	// Prefer the machine associated with the session's volume; fall back to the
	// most recent active machine for the user when no volume match is found.
	machineID := ""
	if tick.VolumeID != "" {
		machineID = c.resolveMachineIDByVolume(ctx, tick.VolumeID)
	}
	if machineID == "" {
		machineID = c.resolveMachineIDByEmail(ctx, email)
	}
	if machineID == "" {
		return fmt.Errorf("no active machine found for session %s (email %s, volume %s)", tick.SessionID, email, tick.VolumeID)
	}
	if err := c.pr.RPC(ctx, "increment_machine_usage", map[string]any{
		"p_machine_id": machineID,
		"p_minutes":    c.sessionMins,
	}, nil); err != nil {
		return err
	}
	stats.sessionBilled++
	stats.events++
	return bus.Publish(ctx, c.bus, model.TopicUsage, model.UsageMsg{
		EventTime:  at,
		UserEmail:  email,
		SessionID:  tick.SessionID,
		Metric:     "session.minutes",
		Value:      float64(c.sessionMins),
		Cluster:    cluster,
		Node:       tick.Node,
		VolumeID:   tick.VolumeID,
		TickBucket: uint64(bucket),
		Source:     "collector",
	})
}

func (c *Collector) applyVolumeUsage(ctx context.Context, email, cluster string, tick VolumeTick, at time.Time, bucket int64, stats *tickStats) error {
	// Volume usage is billed against the machine that owns this volume.
	// Skip silently when no machine is found — the volume may not yet be
	// attached to a machine row (e.g. during provisioning).
	machineID := c.resolveMachineIDByVolume(ctx, tick.VolumeID)
	if machineID == "" {
		return nil
	}
	if err := c.pr.RPC(ctx, "increment_machine_data_usage", map[string]any{
		"p_machine_id": machineID,
		"p_size_gb":    tick.SizeGB,
	}, nil); err != nil {
		return err
	}
	stats.volumeBilled++
	stats.events++
	return bus.Publish(ctx, c.bus, model.TopicUsage, model.UsageMsg{
		EventTime:  at,
		UserEmail:  email,
		SessionID:  tick.VolumeID,
		Metric:     "volume.gb",
		Value:      float64(tick.SizeGB),
		Cluster:    cluster,
		Node:       tick.Node,
		VolumeID:   tick.VolumeID,
		TickBucket: uint64(bucket),
		Source:     "collector",
	})
}
