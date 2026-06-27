// Package jobpoller claims SQL-inserted infra.job rows (scheduler + billing) and
// dispatches them to the volume worker (virtdaemon side effects stay off Postgres).
package jobpoller

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/worker/volume"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// VolumeProcessor runs a claimed infra.job row.
type VolumeProcessor interface {
	HandleClaimed(ctx context.Context, jobID int64, command string, clusterID int64, arguments json.RawMessage, requestID string) error
}

// Poller ticks claim_pending_jobs_v1 and hands rows to the volume worker.
type Poller struct {
	pr    *postgrest.Client
	vol   VolumeProcessor
	every time.Duration
	limit int
}

func New(pr *postgrest.Client, vol VolumeProcessor, every time.Duration) *Poller {
	if every <= 0 {
		every = 5 * time.Second
	}
	return &Poller{pr: pr, vol: vol, every: every, limit: 20}
}

// Run blocks until ctx is cancelled.
func (p *Poller) Run(ctx context.Context, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(p.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.tick(ctx, log)
		}
	}
}

type claimedJob struct {
	ID         int64           `json:"id"`
	Command    string          `json:"command"`
	Cluster    *int64          `json:"cluster"`
	Arguments  json.RawMessage `json:"arguments"`
	RequestID  string          `json:"request_id"`
}

func (p *Poller) tick(ctx context.Context, log *slog.Logger) {
	var jobs []claimedJob
	if err := p.pr.RPC(ctx, "claim_pending_jobs_v1", map[string]any{"p_limit": p.limit}, &jobs); err != nil {
		log.Warn("claim_pending_jobs_v1 failed", "err", err)
		return
	}
	for _, job := range jobs {
		clusterID := int64(0)
		if job.Cluster != nil {
			clusterID = *job.Cluster
		}
		if err := p.vol.HandleClaimed(ctx, job.ID, job.Command, clusterID, job.Arguments, job.RequestID); err != nil {
			log.Warn("claimed job failed", "job_id", job.ID, "command", job.Command, "err", err)
		}
	}
}

var _ VolumeProcessor = (*volume.Handler)(nil)
