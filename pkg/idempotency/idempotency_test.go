package idempotency

import (
	"context"
	"errors"
	"testing"
)

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

func TestRun_ErrorIsRetried(t *testing.T) {
	g := New(NewMemStore())
	ctx := context.Background()
	boom := errors.New("boom")
	if err := g.Run(ctx, "a", func(context.Context) error { return boom }); err != boom {
		t.Fatalf("Run = %v, want boom (nak)", err)
	}
	reran := false
	if err := g.Run(ctx, "a", func(context.Context) error { reran = true; return nil }); err != nil {
		t.Fatalf("second Run = %v, want nil", err)
	}
	if !reran {
		t.Error("errored id was not retried")
	}
}

func TestRun_SkipsWhilePending(t *testing.T) {
	s := NewMemStore()
	g := New(s)
	ctx := context.Background()
	if acquired, _ := s.Register(ctx, "a"); !acquired {
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
