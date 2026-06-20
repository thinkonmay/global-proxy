package main

import (
	"testing"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestBuildJobs(t *testing.T) {
	got, err := buildJobs([]config.SchedulerJob{
		{Name: "clean", Every: "1m", RPC: "clean_expired_subscription"},
		{Name: "verify", Every: "30s", RPC: "verify_all_payment_v2", TimeoutMs: 2000, Args: map[string]any{"p_limit": 5}},
	})
	if err != nil {
		t.Fatalf("buildJobs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].Every != time.Minute || got[0].Timeout != 0 {
		t.Fatalf("job[0] = %+v", got[0])
	}
	if got[1].Every != 30*time.Second || got[1].Timeout != 2*time.Second {
		t.Fatalf("job[1] = %+v", got[1])
	}
	if got[1].Args["p_limit"] != 5 {
		t.Fatalf("job[1] args = %#v", got[1].Args)
	}
}

func TestBuildJobsBadDuration(t *testing.T) {
	if _, err := buildJobs([]config.SchedulerJob{{Name: "x", Every: "soon", RPC: "fn"}}); err == nil {
		t.Fatal("expected parse error for bad duration")
	}
}
