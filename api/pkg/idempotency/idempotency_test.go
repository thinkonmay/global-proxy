package idempotency

import (
	"context"
	"errors"
	"testing"
)

// First delivery acquires and runs fn.
func TestRun_FirstRuns(t *testing.T) {
	g := New(NewMemStore())
	ran := false
	if err := g.Run(context.Background(), "a", func(context.Context) error { ran = true; return nil }); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if !ran {
		t.Error("fn did not run on first delivery")
	}
}

// A duplicate (row exists, not errored) skips without rerunning fn.
func TestRun_DuplicateSkips(t *testing.T) {
	g := New(NewMemStore())
	ctx := context.Background()
	if err := g.Run(ctx, "a", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("first Run = %v", err)
	}
	ran := false
	if err := g.Run(ctx, "a", func(context.Context) error { ran = true; return nil }); err != nil {
		t.Fatalf("duplicate Run = %v, want nil (skip)", err)
	}
	if ran {
		t.Error("fn ran on a duplicate, want skip")
	}
}

// fn error is recorded but acked (nil) and never retried — at most once.
func TestRun_ErrorIsNotRetried(t *testing.T) {
	g := New(NewMemStore())
	ctx := context.Background()
	boom := errors.New("boom")
	if err := g.Run(ctx, "a", func(context.Context) error { return boom }); err != nil {
		t.Fatalf("Run = %v, want nil (ack, no retry)", err)
	}
	reran := false
	if err := g.Run(ctx, "a", func(context.Context) error { reran = true; return nil }); err != nil {
		t.Fatalf("second Run = %v, want nil", err)
	}
	if reran {
		t.Error("errored id was rerun, want at-most-once skip")
	}
}

// failMark is a MemStore whose MarkError always fails (db down).
type failMark struct{ *MemStore }

func (failMark) MarkError(context.Context, string) error { return errors.New("db down") }

// fn fails AND the failure can't be recorded -> ErrRecordFailed (caller escalates).
func TestRun_RecordFailureSurfaces(t *testing.T) {
	g := New(failMark{NewMemStore()})
	err := g.Run(context.Background(), "a", func(context.Context) error { return errors.New("boom") })
	if !errors.Is(err, ErrRecordFailed) {
		t.Fatalf("Run = %v, want ErrRecordFailed", err)
	}
}

// A duplicate arriving while the first is still pending also skips.
func TestRun_SkipsWhilePending(t *testing.T) {
	s := NewMemStore()
	g := New(s)
	ctx := context.Background()
	if acquired, _ := s.Register(ctx, "a"); !acquired { // first still processing
		t.Fatal("seed register must acquire")
	}
	ran := false
	if err := g.Run(ctx, "a", func(context.Context) error { ran = true; return nil }); err != nil {
		t.Fatalf("Run during pending = %v, want nil (skip)", err)
	}
	if ran {
		t.Error("fn ran while another holder is pending, want skip")
	}
}
