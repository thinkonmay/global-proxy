package handler

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func newHandler() *Handler {
	return New(idempotency.New(idempotency.NewMemStore()), nil)
}

// fakeBus captures Publish topics; failPub simulates a down DLQ.
type fakeBus struct {
	mu      sync.Mutex
	topics  []string
	failPub bool
}

func (f *fakeBus) Publish(_ context.Context, topic string, _ []byte) error {
	if f.failPub {
		return errors.New("bus down")
	}
	f.mu.Lock()
	f.topics = append(f.topics, topic)
	f.mu.Unlock()
	return nil
}
func (f *fakeBus) Subscribe(string, string, bus.Handler, bus.SubscribeOptions) {}
func (f *fakeBus) Ping() error  { return nil }
func (f *fakeBus) Close() error { return nil }

// failMarkStore is a MemStore whose MarkError always fails (db down).
type failMarkStore struct{ *idempotency.MemStore }

func (failMarkStore) MarkError(context.Context, string) error { return errors.New("db down") }

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

// fn fails AND the store can't record it -> escalate to the DLQ topic, then ack.
func TestHandleJob_EscalatesToDLQWhenRecordFails(t *testing.T) {
	fb := &fakeBus{}
	h := New(idempotency.New(failMarkStore{idempotency.NewMemStore()}), fb)
	h.run = func(context.Context, model.JobMsg) error { return errors.New("fn boom") }

	if err := h.handleJob(context.Background(), model.JobMsg{ID: "j1"}); err != nil {
		t.Fatalf("handleJob = %v, want nil (acked after DLQ)", err)
	}
	if len(fb.topics) != 1 || fb.topics[0] != "jobs.DLQ" {
		t.Fatalf("DLQ publishes = %v, want [jobs.DLQ]", fb.topics)
	}
}

// DLQ also down: ack anyway (no recovery possible), don't nak.
func TestHandleJob_DLQDownStillAcks(t *testing.T) {
	h := New(idempotency.New(failMarkStore{idempotency.NewMemStore()}), &fakeBus{failPub: true})
	h.run = func(context.Context, model.JobMsg) error { return errors.New("fn boom") }

	if err := h.handleJob(context.Background(), model.JobMsg{ID: "j1"}); err != nil {
		t.Fatalf("handleJob = %v, want nil (ack, accept loss)", err)
	}
}
