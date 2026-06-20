package model

import (
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

var TopicVolumeJob = bus.NewTopic[VolumeJobEnvelope]("jobs.volume")
var TopicVolumeDLQ = bus.NewTopic[VolumeJobEnvelope]("jobs.volume.dlq")
var TopicJob = TopicVolumeJob // legacy alias

type VolumeJobEnvelope struct {
	OutboxID   int64           `json:"outbox_id"`
	Topic      string          `json:"topic"`
	OccurredAt string          `json:"occurred_at,omitempty"`
	TraceID    string          `json:"trace_id,omitempty"`
	Payload    VolumeJobPayload `json:"payload"`
}

type VolumeJobPayload struct {
	Command       string          `json:"command"`
	JobID         int64           `json:"job_id"`
	ClusterID     int64           `json:"cluster_id"`
	Email         string          `json:"email"`
	VolumeID      string          `json:"volume_id"`
	Configuration json.RawMessage `json:"configuration"`
	TargetDomain  string          `json:"target_domain"`
}

// JobMsg kept for dev-only POST /jobs path.
type JobMsg struct {
	ID        string          `json:"id"`
	Command   string          `json:"command"`
	Arguments json.RawMessage `json:"arguments"`
}
