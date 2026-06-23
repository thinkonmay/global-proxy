package model

import (
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

var TopicVolumeJob = bus.NewTopic[VolumeJobMsg]("jobs.volume")

// VolumeJobMsg is a volume-lifecycle job on the bus. The gateway publishes the
// thin set (RequestID, Command, ClusterID, TargetDomain, Arguments); the worker
// is the sole DB writer — it inserts the job row (dedup on RequestID), fills
// JobID, and derives Email/VolumeID/Configuration from Arguments.
type VolumeJobMsg struct {
	// RequestID is the gateway-generated idempotency key. The worker dedups the
	// insert + side effects on it; the client tracks the job by it.
	RequestID string `json:"request_id"`
	Command   string `json:"command"`
	ClusterID int64  `json:"cluster_id"`
	// Arguments is the raw client argument object, persisted to job.arguments.
	Arguments    json.RawMessage `json:"arguments"`
	TargetDomain string          `json:"target_domain"`

	// Filled by the worker (not on the wire from the gateway).
	JobID         int64           `json:"job_id"`
	Email         string          `json:"email"`
	VolumeID      string          `json:"volume_id"`
	Configuration json.RawMessage `json:"configuration"`
}
