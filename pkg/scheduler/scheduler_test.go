package scheduler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewValidation(t *testing.T) {
	noop := func(context.Context, string, any, any) error { return nil }
	cases := map[string][]Job{
		"no jobs":      nil,
		"missing rpc":  {{Name: "a", Every: time.Second}},
		"missing name": {{RPC: "fn", Every: time.Second}},
		"bad interval": {{Name: "a", RPC: "fn", Every: 0}},
	}
	for name, jobs := range cases {
		if _, err := New(noop, jobs, quietLogger()); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := New(nil, []Job{{Name: "a", RPC: "fn", Every: time.Second}}, quietLogger()); err == nil {
		t.Error("nil rpc: expected error")
	}
}

func TestNewAppliesDefaultTimeout(t *testing.T) {
	noop := func(context.Context, string, any, any) error { return nil }
	s, err := New(noop, []Job{{Name: "a", RPC: "fn", Every: time.Second}}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if s.runners[0].job.Timeout != defaultTimeout {
		t.Fatalf("timeout = %v, want %v", s.runners[0].job.Timeout, defaultTimeout)
	}
}

func TestTickCallsRPCWithArgs(t *testing.T) {
	var (
		gotFn   string
		gotArgs any
	)
	rpc := func(_ context.Context, fn string, args, _ any) error {
		gotFn, gotArgs = fn, args
		return nil
	}
	s, err := New(rpc, []Job{{
		Name:  "verify",
		RPC:   "verify_all_payment_v2",
		Every: time.Hour,
		Args:  map[string]any{"p_limit": 10},
	}}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), s.runners[0])

	if gotFn != "verify_all_payment_v2" {
		t.Fatalf("fn = %q", gotFn)
	}
	m, ok := gotArgs.(map[string]any)
	if !ok || m["p_limit"] != 10 {
		t.Fatalf("args = %#v", gotArgs)
	}
}

func TestTickNoArgsSendsNilBody(t *testing.T) {
	var gotArgs any = "sentinel"
	rpc := func(_ context.Context, _ string, args, _ any) error {
		gotArgs = args
		return nil
	}
	s, err := New(rpc, []Job{{Name: "clean", RPC: "clean_expired_subscription", Every: time.Hour}}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), s.runners[0])
	if gotArgs != nil {
		t.Fatalf("expected nil args for no-arg RPC, got %#v", gotArgs)
	}
}

func TestTickAppliesTimeout(t *testing.T) {
	var hadDeadline bool
	rpc := func(ctx context.Context, _ string, _, _ any) error {
		_, hadDeadline = ctx.Deadline()
		return nil
	}
	s, err := New(rpc, []Job{{Name: "a", RPC: "fn", Every: time.Hour, Timeout: 50 * time.Millisecond}}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), s.runners[0])
	if !hadDeadline {
		t.Fatal("expected per-tick context deadline")
	}
}

func TestTickErrorDoesNotPanic(t *testing.T) {
	rpc := func(context.Context, string, any, any) error { return errors.New("boom") }
	s, err := New(rpc, []Job{{Name: "a", RPC: "fn", Every: time.Hour}}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), s.runners[0]) // must return cleanly on RPC error
}

// TestTickSkipsOverlap proves a second tick is dropped while the first is still
// in flight, so a slow RPC cannot pile up concurrent runs.
func TestTickSkipsOverlap(t *testing.T) {
	var concurrent atomic.Int32
	var calls atomic.Int32
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	rpc := func(context.Context, string, any, any) error {
		calls.Add(1)
		concurrent.Add(1)
		defer concurrent.Add(-1)
		entered <- struct{}{}
		<-release
		return nil
	}
	s, err := New(rpc, []Job{{Name: "a", RPC: "fn", Every: time.Hour, Timeout: time.Second}}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.tick(context.Background(), s.runners[0]) }()

	<-entered // first tick is inside the RPC and holding the running flag
	s.tick(context.Background(), s.runners[0]) // second tick should skip immediately

	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("rpc calls = %d, want 1 (overlap should be skipped)", got)
	}
	if got := concurrent.Load(); got != 0 {
		t.Fatalf("concurrent leftover = %d", got)
	}
}

// TestRunTicksUntilCancel checks the ticker loop fires and stops on context cancel.
func TestRunTicksUntilCancel(t *testing.T) {
	var calls atomic.Int32
	rpc := func(context.Context, string, any, any) error {
		calls.Add(1)
		return nil
	}
	s, err := New(rpc, []Job{{Name: "a", RPC: "fn", Every: 5 * time.Millisecond, Timeout: time.Second}}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("scheduler did not tick in time")
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
