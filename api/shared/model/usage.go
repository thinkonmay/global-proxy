package model

import (
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// TopicUsage carries usage snapshots to the ClickHouse sink (cmd/usagesink).
var TopicUsage = bus.NewTopic[UsageEvent]("usage.snapshot")

// UsageEvent is one usage data point (session hours, data, LLM tokens, ...).
// Mirrors the ClickHouse usage_events columns.
type UsageEvent struct {
	EventTime time.Time `json:"event_time"`
	UserEmail string    `json:"user_email"`
	SessionID string    `json:"session_id"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Cluster   string    `json:"cluster"`
}
