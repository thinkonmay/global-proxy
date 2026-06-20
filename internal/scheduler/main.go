// Command scheduler is the global pg_cron replacement (D15/P14). It ticks a set
// of PostgREST RPCs on fixed intervals (config: scheduler.jobs[]) instead of
// running cron.schedule entries inside Postgres. Billing/cleanup SQL stays in
// Postgres functions (P5); this worker only triggers them over PostgREST (P13).
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/scheduler"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.SetupLogger()

	if !cfg.Scheduler.Enabled {
		slog.Info("scheduler disabled (set APP_SCHEDULER_ENABLED=1); exiting")
		return
	}

	var jobs []scheduler.Job
	if cfg.Scheduler.Enabled {
		var err error
		jobs, err = buildJobs(cfg.Scheduler.Jobs)
		if err != nil {
			log.Fatalf("scheduler jobs: %v", err)
		}
	}

	pr := postgrest.New(postgrest.Config{
		URL:        cfg.PostgREST.URL,
		AnonKey:    cfg.PostgREST.AnonKey,
		ServiceKey: cfg.PostgREST.ServiceKey,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.Scheduler.Enabled && len(jobs) > 0 {
		sch, err := scheduler.New(pr.RPC, jobs, slog.Default())
		if err != nil {
			log.Fatalf("build scheduler: %v", err)
		}
		slog.Info("scheduler started", "jobs", len(jobs))
		go sch.Run(ctx)
	} else if cfg.Scheduler.Enabled {
		slog.Info("scheduler enabled but no jobs configured")
	}
	<-ctx.Done()
	slog.Info("scheduler stopped")
}

// buildJobs maps validated config into scheduler jobs, parsing the `every`
// duration string and converting timeoutMs to a Duration.
func buildJobs(cfgJobs []config.SchedulerJob) ([]scheduler.Job, error) {
	jobs := make([]scheduler.Job, 0, len(cfgJobs))
	for _, jc := range cfgJobs {
		every, err := time.ParseDuration(jc.Every)
		if err != nil {
			return nil, fmt.Errorf("job %q: parse every %q: %w", jc.Name, jc.Every, err)
		}
		var timeout time.Duration
		if jc.TimeoutMs > 0 {
			timeout = time.Duration(jc.TimeoutMs) * time.Millisecond
		}
		jobs = append(jobs, scheduler.Job{
			Name:    jc.Name,
			Every:   every,
			RPC:     jc.RPC,
			Args:    jc.Args,
			Timeout: timeout,
		})
	}
	return jobs, nil
}
