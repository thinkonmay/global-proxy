package model

import (
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// TopicUsage carries usage snapshots to the worker's ClickHouse sink.
var TopicUsage = bus.NewTopic[UsageMsg]("usage.snapshot")

// UsageMsg is one usage data point (session hours, data, LLM tokens, ...).
// Mirrors the ClickHouse usage_events columns.
type UsageMsg struct {
	EventTime  time.Time `json:"event_time"`
	UserEmail  string    `json:"user_email"`
	SessionID  string    `json:"session_id"`
	Metric     string    `json:"metric"`
	Value      float64   `json:"value"`
	Cluster    string    `json:"cluster"`
	Node       string    `json:"node,omitempty"`
	VolumeID   string    `json:"volume_id,omitempty"`
	TickBucket uint64    `json:"tick_bucket,omitempty"`
	Source     string    `json:"source,omitempty"`
}
