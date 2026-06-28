package rybbit

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/config"
)

const chPingTimeout = 3 * time.Second

// ClickHouseConfig mirrors platform CH settings for the Rybbit analytics instance.
type ClickHouseConfig struct {
	Addr     string
	Database string
	Username string
	Password string
}

// ConfigFromGateway maps gateway CDP Rybbit settings.
func ConfigFromGateway(cfg config.ClickHouse) ClickHouseConfig {
	return ClickHouseConfig{
		Addr:     cfg.Addr,
		Database: cfg.Database,
		Username: cfg.Username,
		Password: cfg.Password,
	}
}

// OpenCH connects to rybbit-clickhouse (separate from platform ClickHouse).
func OpenCH(cfg ClickHouseConfig) (driver.Conn, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("rybbit clickhouse addr is empty")
	}
	db := cfg.Database
	if db == "" {
		db = "analytics"
	}
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.Addr},
		Auth: clickhouse.Auth{
			Database: db,
			Username: cfg.Username,
			Password: cfg.Password,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("rybbit clickhouse open: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), chPingTimeout)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("rybbit clickhouse ping: %w", err)
	}
	return conn, nil
}

// UserRollup is a 30-day web engagement snapshot keyed by Rybbit user_id (PocketBase id).
type UserRollup struct {
	UserID       string    `ch:"user_id"`
	Pageviews    uint64    `ch:"pageviews"`
	CustomEvents uint64    `ch:"custom_events"`
	Sessions     uint64    `ch:"sessions"`
	TopPaths     []string  `ch:"top_paths"`
	TopEvents    []string  `ch:"top_events"`
	LastSeen     time.Time `ch:"last_seen"`
}

// Querier reads batched rollups from Rybbit ClickHouse events table.
type Querier struct {
	ch driver.Conn
}

func NewQuerier(ch driver.Conn) *Querier {
	return &Querier{ch: ch}
}

// RollupsBySite returns per-user web rollups for the lookback window.
func (q *Querier) RollupsBySite(ctx context.Context, siteID int, days int) ([]UserRollup, error) {
	if siteID <= 0 {
		return nil, fmt.Errorf("rybbit site id required")
	}
	if days <= 0 {
		days = 30
	}
	var rows []UserRollup
	err := q.ch.Select(ctx, &rows, `
		SELECT
			user_id,
			countIf(type = 'pageview') AS pageviews,
			countIf(type = 'custom_event') AS custom_events,
			uniqExact(session_id) AS sessions,
			topK(8)(pathname) AS top_paths,
			arrayFilter(x -> x != '', topK(8)(if(type = 'custom_event', event_name, ''))) AS top_events,
			max(timestamp) AS last_seen
		FROM events
		WHERE site_id = ?
		  AND user_id != ''
		  AND timestamp >= now() - INTERVAL ? DAY
		GROUP BY user_id
		HAVING pageviews > 0 OR custom_events > 0
	`, siteID, days)
	return rows, err
}
