// Package scheduler is the global pg_cron replacement (D15/P14): instead of
// Postgres running cron.schedule entries, a Go worker fires PostgREST RPCs on
// fixed intervals. Billing/cleanup logic stays in Postgres functions (P5); this
// only triggers them on a timer, over PostgREST (P13) — no direct DB access.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// defaultTimeout bounds a tick when a job sets none.
const defaultTimeout = 5 * time.Second

// RPCFunc calls a PostgREST RPC. It matches (*postgrest.Client).RPC so the real
// client can be passed directly; dest is nil for these fire-and-forget sweeps.
type RPCFunc func(ctx context.Context, fn string, args, dest any) error

// Job is one timer-driven RPC.
type Job struct {
	Name    string         // log/identity label
	Every   time.Duration  // tick interval (> 0)
	RPC     string         // Postgres function name (POST /rpc/<RPC>)
	Args    map[string]any // optional RPC args; nil/empty sends no body
	Timeout time.Duration  // per-tick deadline; <= 0 uses defaultTimeout
}

// Scheduler runs each Job on its own ticker until the context is cancelled.
type Scheduler struct {
	rpc     RPCFunc
	log     *slog.Logger
	runners []*runner
}

type runner struct {
	job     Job
	running atomic.Bool
}

// New validates jobs and builds a Scheduler. It errors on an empty job set or a
// job missing a name/rpc or with a non-positive interval, so a misconfigured
// worker fails fast at boot rather than silently doing nothing.
func New(rpc RPCFunc, jobs []Job, log *slog.Logger) (*Scheduler, error) {
	if rpc == nil {
		return nil, errors.New("scheduler: nil rpc func")
	}
	if log == nil {
		log = slog.Default()
	}
	if len(jobs) == 0 {
		return nil, errors.New("scheduler: no jobs configured")
	}
	runners := make([]*runner, 0, len(jobs))
	for _, j := range jobs {
		if j.Name == "" || j.RPC == "" {
			return nil, fmt.Errorf("scheduler: job missing name or rpc: %+v", j)
		}
		if j.Every <= 0 {
			return nil, fmt.Errorf("scheduler: job %q: interval must be > 0", j.Name)
		}
		if j.Timeout <= 0 {
			j.Timeout = defaultTimeout
		}
		runners = append(runners, &runner{job: j})
	}
	return &Scheduler{rpc: rpc, log: log, runners: runners}, nil
}

// Run starts one goroutine per job and blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, r := range s.runners {
		wg.Add(1)
		go func(r *runner) {
			defer wg.Done()
			s.log.Info("scheduler job registered", "job", r.job.Name, "every", r.job.Every, "rpc", r.job.RPC)
			t := time.NewTicker(r.job.Every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					s.tick(ctx, r)
				}
			}
		}(r)
	}
	wg.Wait()
}

// tick runs one invocation, skipping if the previous one is still in flight so a
// slow RPC cannot pile up (overlap guard). Each call gets its own timeout.
func (s *Scheduler) tick(ctx context.Context, r *runner) {
	if !r.running.CompareAndSwap(false, true) {
		s.log.Warn("scheduler skip: previous tick still running", "job", r.job.Name)
		return
	}
	defer r.running.Store(false)

	cctx, cancel := context.WithTimeout(ctx, r.job.Timeout)
	defer cancel()

	start := time.Now()
	if err := s.rpc(cctx, r.job.RPC, argsOrNil(r.job.Args), nil); err != nil {
		s.log.Error("scheduler job failed", "job", r.job.Name, "rpc", r.job.RPC, "err", err)
		return
	}
	s.log.Info("scheduler job ok", "job", r.job.Name, "took", time.Since(start))
}

// argsOrNil returns nil for an empty arg map so PostgREST receives no body and
// treats it as a no-argument RPC call.
func argsOrNil(args map[string]any) any {
	if len(args) == 0 {
		return nil
	}
	return args
}
