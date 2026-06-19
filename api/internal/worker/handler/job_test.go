package handler

import (
	"context"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func newHandler() *Handler {
	return New(idempotency.New(idempotency.NewMemStore()), nil, nil)
}

func TestHandleJob_RunsAndAcks(t *testing.T) {
	h := newHandler()
	if err := h.handleJob(context.Background(), model.JobMsg{ID: "j1", Command: "x"}); err != nil {
		t.Fatalf("handleJob = %v, want nil (ack)", err)
	}
}

// A duplicate id skips and still acks (nil) — never re-runs, never errors.
func TestHandleJob_DuplicateSkipsAndAcks(t *testing.T) {
	h := newHandler()
	ctx := context.Background()
	if err := h.handleJob(ctx, model.JobMsg{ID: "j1"}); err != nil {
		t.Fatalf("first = %v", err)
	}
	if err := h.handleJob(ctx, model.JobMsg{ID: "j1"}); err != nil {
		t.Fatalf("duplicate = %v, want nil (skip-ack)", err)
	}
}
