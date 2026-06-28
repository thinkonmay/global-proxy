package cdp

import "time"

// FrontendRollup is stored in events.cdp_event_log (source=rybbit_etl, kind=frontend_rollup).
type FrontendRollup struct {
	LookbackDays int       `json:"lookback_days"`
	Pageviews    uint64    `json:"pageviews"`
	CustomEvents uint64    `json:"custom_events"`
	Sessions     uint64    `json:"sessions"`
	TopPaths     []string  `json:"top_paths"`
	TopEvents    []string  `json:"top_events"`
	LastSeen     string    `json:"last_seen,omitempty"`
	SyncedAt     string    `json:"synced_at"`
}

// BuildFrontendRollup maps a Rybbit CH row into the CDP payload shape.
func BuildFrontendRollup(days int, pageviews, customEvents, sessions uint64, topPaths, topEvents []string, lastSeen time.Time, syncedAt time.Time) FrontendRollup {
	if topPaths == nil {
		topPaths = []string{}
	}
	if topEvents == nil {
		topEvents = []string{}
	}
	out := FrontendRollup{
		LookbackDays: days,
		Pageviews:    pageviews,
		CustomEvents: customEvents,
		Sessions:     sessions,
		TopPaths:     topPaths,
		TopEvents:    topEvents,
		SyncedAt:     syncedAt.UTC().Format(time.RFC3339),
	}
	if !lastSeen.IsZero() {
		out.LastSeen = lastSeen.UTC().Format(time.RFC3339)
	}
	return out
}
