package model

import (
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// TopicAppUsage carries batched VM process rollups to the worker ClickHouse sink.
var TopicAppUsage = bus.NewTopic[AppUsageMsg]("usage.app_snapshot")

// AppUsageMsg is one app rollup row from a virtdaemon process-analytics flush.
// Mirrors platform.session_app_usage columns.
type AppUsageMsg struct {
	EventTime        time.Time `json:"event_time"`
	UserEmail        string    `json:"user_email"`
	RuntimeSessionID string    `json:"runtime_session_id"`
	AppKey           string    `json:"app_key"`
	DurationSec      float64   `json:"duration_sec"`
	LaunchCount      uint32    `json:"launch_count,omitempty"`
	Cluster          string    `json:"cluster"`
	Node             string    `json:"node,omitempty"`
	FlushReason      string    `json:"flush_reason,omitempty"`
	FlushSeq         uint64    `json:"flush_seq,omitempty"`
	Source           string    `json:"source,omitempty"`
}
