// Command usage-backfill loads legacy vm_snapshoot_v4 and volume_snapshoot rows into
// platform ClickHouse usage_events with source=backfill (audit/history only).
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const insertSQL = `INSERT INTO usage_events (
	event_time, user_email, session_id, metric, value, cluster,
	node, volume_id, tick_bucket, source
)`

func main() {
	legacyURL := flag.String("legacy-db", os.Getenv("LEGACY_DATABASE_URL"), "legacy Postgres URL (vm_snapshoot_v4, volume_snapshoot)")
	batchSize := flag.Int("batch", 5000, "rows per ClickHouse batch")
	dryRun := flag.Bool("dry-run", false, "count rows only")
	flag.Parse()

	if *legacyURL == "" {
		log.Fatal("LEGACY_DATABASE_URL or -legacy-db required")
	}

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ch, err := usage.OpenCH(cfg.ClickHouse)
	if err != nil {
		log.Fatalf("clickhouse: %v", err)
	}
	defer ch.Close()

	pg, err := sql.Open("pgx", *legacyURL)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer pg.Close()

	ctx := context.Background()
	if err := pg.PingContext(ctx); err != nil {
		log.Fatalf("postgres ping: %v", err)
	}
	if err := ch.Ping(ctx); err != nil {
		log.Fatalf("clickhouse ping: %v", err)
	}

	vmCount, err := backfillVM(ctx, pg, ch, *batchSize, *dryRun)
	if err != nil {
		log.Fatalf("vm backfill: %v", err)
	}
	volCount, err := backfillVolume(ctx, pg, ch, *batchSize, *dryRun)
	if err != nil {
		log.Fatalf("volume backfill: %v", err)
	}
	log.Printf("done: vm_rows=%d volume_rows=%d dry_run=%v", vmCount, volCount, *dryRun)
}

func backfillVM(ctx context.Context, pg *sql.DB, ch driver.Conn, batchSize int, dryRun bool) (int, error) {
	rows, err := pg.QueryContext(ctx, `
		SELECT v.created_at, v.email, v.session_id::text, v.volume_id::text, v.node,
		       COALESCE(c.domain, '') AS cluster
		FROM vm_snapshoot_v4 v
		LEFT JOIN clusters c ON c.id = v.cluster_id
		ORDER BY v.id
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	total := 0
	batch := make([]model.UsageMsg, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 || dryRun {
			batch = batch[:0]
			return nil
		}
		if err := insertBatch(ctx, ch, batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}

	for rows.Next() {
		var (
			at                              time.Time
			email, sessionID, volumeID, node string
			cluster                         string
		)
		if err := rows.Scan(&at, &email, &sessionID, &volumeID, &node, &cluster); err != nil {
			return total, err
		}
		batch = append(batch, model.UsageMsg{
			EventTime: at.UTC(),
			UserEmail: email,
			SessionID: sessionID,
			Metric:    "session.minutes",
			Value:     5,
			Cluster:   cluster,
			Node:      node,
			VolumeID:  volumeID,
			Source:    "backfill",
		})
		total++
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return total, err
	}
	return total, flush()
}

func backfillVolume(ctx context.Context, pg *sql.DB, ch driver.Conn, batchSize int, dryRun bool) (int, error) {
	rows, err := pg.QueryContext(ctx, `
		SELECT created_at, email, name::text, size_in_gb
		FROM volume_snapshoot
		ORDER BY id
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	total := 0
	batch := make([]model.UsageMsg, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 || dryRun {
			batch = batch[:0]
			return nil
		}
		if err := insertBatch(ctx, ch, batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}

	for rows.Next() {
		var at time.Time
		var email, volumeID string
		var sizeGB int64
		if err := rows.Scan(&at, &email, &volumeID, &sizeGB); err != nil {
			return total, err
		}
		batch = append(batch, model.UsageMsg{
			EventTime: at.UTC(),
			UserEmail: email,
			SessionID: volumeID,
			Metric:    "volume.gb",
			Value:     float64(sizeGB),
			VolumeID:  volumeID,
			Source:    "backfill",
		})
		total++
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return total, err
	}
	return total, flush()
}

func insertBatch(ctx context.Context, ch driver.Conn, events []model.UsageMsg) error {
	b, err := ch.PrepareBatch(ctx, insertSQL)
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}
	for _, e := range events {
		source := e.Source
		if source == "" {
			source = "backfill"
		}
		if err := b.Append(
			e.EventTime, e.UserEmail, e.SessionID, e.Metric, e.Value, e.Cluster,
			e.Node, e.VolumeID, e.TickBucket, source,
		); err != nil {
			return err
		}
	}
	return b.Send()
}
