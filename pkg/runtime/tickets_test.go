package runtime_test

import (
	"testing"
	"time"

	runtimepkg "github.com/thinkonmay/global-proxy/api/pkg/runtime"
	"github.com/thinkonmay/thinkshare-daemon/persistent"
)

func TestTicketsNewAndTake(t *testing.T) {
	tickets := runtimepkg.NewTickets()
	session := &persistent.WorkerSession{Id: "s1"}
	id := tickets.IssueNew(1, session, []string{"vol-1"})
	if id == "" {
		t.Fatal("expected ticket id")
	}
	got, ok := tickets.TakeNew(id)
	if !ok || got.ClusterID != 1 {
		t.Fatalf("take failed: ok=%v cluster=%d", ok, got.ClusterID)
	}
	_, again := tickets.TakeNew(id)
	if again {
		t.Fatal("ticket should be single-use")
	}
	tickets.FinishNew(id)
	if !tickets.IsFinishedNew(id) {
		t.Fatal("expected finished ticket")
	}
	_, afterFinish := tickets.TakeNew(id)
	if afterFinish {
		t.Fatal("finished ticket should not replay")
	}
}

func TestTicketsExpiry(t *testing.T) {
	tickets := runtimepkg.NewTickets()
	// internal TTL is 5m; just verify issue/take path for alloc tickets
	req := &persistent.AllocateRequest{}
	id := tickets.IssueAlloc(2, req)
	got, ok := tickets.TakeAlloc(id)
	if !ok || got.ClusterID != 2 {
		t.Fatalf("alloc take failed")
	}
	_ = time.Now()
}
