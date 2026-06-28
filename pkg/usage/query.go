package usage

import (
	"context"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Querier reads usage analytics from platform ClickHouse (audit log only; not billing).
type Querier struct {
	ch driver.Conn
}

func NewQuerier(ch driver.Conn) *Querier {
	return &Querier{ch: ch}
}

// HeatmapEntry matches get_user_heatmap RPC rows.
type HeatmapEntry struct {
	UsageDate  time.Time `json:"usage_date" ch:"usage_date"`
	TotalHours float64   `json:"total_hours" ch:"total_hours"`
}

// DataUsageEntry matches get_data_usage RPC rows.
type DataUsageEntry struct {
	Name      string    `json:"name" ch:"name"`
	CreatedAt time.Time `json:"created_at" ch:"created_at"`
	SizeInGB  int64     `json:"size_in_gb" ch:"size_in_gb"`
}

// AppUsageEntry is one aggregated app row for persona / recommendations.
type AppUsageEntry struct {
	AppKey      string  `json:"app_key" ch:"app_key"`
	DurationSec float64 `json:"duration_sec" ch:"duration_sec"`
	LaunchCount uint64  `json:"launch_count" ch:"launch_count"`
}

// AppUsageByEmail returns top apps by dwell time for the last days (default 30).
func (q *Querier) AppUsageByEmail(ctx context.Context, email string, days int, limit int) ([]AppUsageEntry, error) {
	if days <= 0 {
		days = 30
	}
	if limit <= 0 {
		limit = 30
	}
	var rows []AppUsageEntry
	err := q.ch.Select(ctx, &rows, `
		SELECT
			app_key,
			sum(duration_sec) AS duration_sec,
			sum(launch_count) AS launch_count
		FROM session_app_usage
		WHERE user_email = ?
		  AND event_time >= now() - INTERVAL ? DAY
		GROUP BY app_key
		ORDER BY duration_sec DESC
		LIMIT ?
	`, email, days, limit)
	return rows, err
}

// Heatmap returns daily session hours for the last days (default 365).
func (q *Querier) Heatmap(ctx context.Context, email string, days int) ([]HeatmapEntry, error) {
	if days <= 0 {
		days = 365
	}
	var rows []HeatmapEntry
	err := q.ch.Select(ctx, &rows, `
		SELECT
			toDate(event_time) AS usage_date,
			sum(value) / 60.0 AS total_hours
		FROM usage_events
		WHERE user_email = ?
		  AND metric = 'session.minutes'
		  AND event_time >= now() - INTERVAL ? DAY
		GROUP BY usage_date
		ORDER BY usage_date ASC
	`, email, days)
	return rows, err
}

// DailySessionCount counts session.minutes events today (vm_snapshoot_v4 row parity).
func (q *Querier) DailySessionCount(ctx context.Context, email string) (int, error) {
	var count uint64
	err := q.ch.QueryRow(ctx, `
		SELECT count()
		FROM usage_events
		WHERE user_email = ?
		  AND metric = 'session.minutes'
		  AND toDate(event_time) = today()
	`, email).Scan(&count)
	return int(count), err
}

// PlayStreak counts consecutive calendar days with session usage ending today.
func (q *Querier) PlayStreak(ctx context.Context, email string) (int, error) {
	var streak uint64
	err := q.ch.QueryRow(ctx, `
		WITH daily AS (
			SELECT DISTINCT toDate(event_time) AS d
			FROM usage_events
			WHERE user_email = ?
			  AND metric = 'session.minutes'
			  AND event_time >= now() - INTERVAL 60 DAY
		),
		numbered AS (
			SELECT d, d + toInt32(row_number() OVER (ORDER BY d DESC)) AS grp
			FROM daily
		)
		SELECT count() AS streak
		FROM numbered
		WHERE grp = (SELECT grp FROM numbered WHERE d = today() LIMIT 1)
	`, email).Scan(&streak)
	return int(streak), err
}

// DataUsageHistory returns recent volume.gb snapshots per volume (limit default 168).
func (q *Querier) DataUsageHistory(ctx context.Context, email string, limit int) ([]DataUsageEntry, error) {
	if limit <= 0 {
		limit = 168
	}
	var rows []DataUsageEntry
	err := q.ch.Select(ctx, &rows, `
		SELECT
			session_id AS name,
			max(event_time) AS created_at,
			toInt64(argMax(value, event_time)) AS size_in_gb
		FROM usage_events
		WHERE user_email = ?
		  AND metric = 'volume.gb'
		GROUP BY session_id
		ORDER BY created_at DESC
		LIMIT ?
	`, email, limit)
	return rows, err
}
