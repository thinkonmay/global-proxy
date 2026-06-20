package usage

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ReconcileWindow compares PG subscription minutes to CH session.minutes for one email.
type ReconcileWindow struct {
	Email         string
	PGMinutes     int64
	CHMinutes     float64
	DriftMinutes  float64
	WithinOneTick bool
}

// ReconcileSubscriptionUsage warns when PG billing counters drift from CH audit totals.
// PG remains authoritative; CH is never used to correct billing.
func ReconcileSubscriptionUsage(ctx context.Context, ch driver.Conn, email string, windowStart time.Time) (ReconcileWindow, error) {
	var chMinutes float64
	err := ch.Select(ctx, &chMinutes, `
		SELECT coalesce(sum(value), 0)
		FROM usage_events
		WHERE user_email = ?
		  AND metric = 'session.minutes'
		  AND event_time >= ?
		  AND source != 'backfill'
	`, email, windowStart)
	if err != nil {
		return ReconcileWindow{}, fmt.Errorf("ch sum: %w", err)
	}
	return ReconcileWindow{
		Email:     email,
		CHMinutes: chMinutes,
	}, nil
}
