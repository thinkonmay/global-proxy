package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/thinkonmay/global-proxy/api/shared/repo"
)

// ErrLocked means the message is held by another worker (lease not yet expired).
var ErrLocked = errors.New("message locked by another worker")

// process claims a message (idempotency + lock) then runs fn under the lock:
//   - already done -> skip (nil)
//   - locked       -> ErrLocked
//   - acquired     -> run fn; fn error => MarkError + return; fn nil => MarkDone
//
// The returned error drives the bus ack/nak (nil = ack, else nak).
func (h *Handler) process(ctx context.Context, id string, lease time.Duration, fn func(context.Context) error) error {
	status, err := h.repo.ClaimMessage(ctx, id, lease)
	if err != nil {
		return fmt.Errorf("claim %s: %w", id, err)
	}
	switch status {
	case repo.ClaimDone:
		return nil
	case repo.ClaimLocked:
		return ErrLocked
	}
	if err := fn(ctx); err != nil {
		_ = h.repo.MarkError(ctx, id) // release lock, leave for retry
		return fmt.Errorf("run %s: %w", id, err)
	}
	return h.repo.MarkDone(ctx, id)
}
