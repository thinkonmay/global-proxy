package repo

import (
	"context"
	"time"
)

// Claim outcomes returned by the claim_message RPC.
const (
	ClaimAcquired = "acquired" // lease taken — run the side-effect
	ClaimDone     = "done"     // already processed — skip
	ClaimLocked   = "locked"   // held by another worker — retry later
)

// ClaimMessage atomically checks idempotency and acquires the lock for leaseTime.
func (r *Repo) ClaimMessage(ctx context.Context, id string, leaseTime time.Duration) (string, error) {
	var status string
	err := r.pr.RPC(ctx, "claim_message", map[string]any{
		"p_id": id, "p_lease_secs": leaseTime.Seconds(),
	}, &status)
	return status, err
}

// MarkDone records success and clears the lock.
func (r *Repo) MarkDone(ctx context.Context, id string) error {
	return r.pr.RPC(ctx, "mark_done", map[string]any{"p_id": id}, nil)
}

// MarkError records failure and clears the lock so the message can be retried.
func (r *Repo) MarkError(ctx context.Context, id string) error {
	return r.pr.RPC(ctx, "mark_error", map[string]any{"p_id": id}, nil)
}
