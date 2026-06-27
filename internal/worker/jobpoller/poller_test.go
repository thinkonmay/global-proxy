package jobpoller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

type stubVolume struct {
	called int32
	lastID int64
}

func (s *stubVolume) HandleClaimed(ctx context.Context, jobID int64, command string, clusterID int64, arguments json.RawMessage, requestID string) error {
	atomic.AddInt32(&s.called, 1)
	s.lastID = jobID
	return nil
}

func TestPollerClaimsAndDispatches(t *testing.T) {
	stub := &stubVolume{}
	var returned int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/claim_pending_jobs_v1" {
			http.NotFound(w, r)
			return
		}
		if atomic.AddInt32(&returned, 1) > 1 {
			_ = json.NewEncoder(w).Encode([]map[string]any{})
			return
		}
		cluster := int64(3)
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":         42,
			"command":    "snapshot all v1",
			"cluster":    cluster,
			"arguments":  map[string]any{"volume_ids": []string{"vol-1"}},
			"request_id": "sched-snapshot-3-20250627",
		}})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	p := New(pr, stub, time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, nil)
	time.Sleep(20 * time.Millisecond)
	cancel()

	if atomic.LoadInt32(&stub.called) != 1 {
		t.Fatalf("HandleClaimed calls = %d, want 1", stub.called)
	}
	if stub.lastID != 42 {
		t.Fatalf("job id = %d, want 42", stub.lastID)
	}
}
