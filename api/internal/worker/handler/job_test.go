package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
	"github.com/thinkonmay/global-proxy/api/shared/repo"
)

type hits struct{ claim, done, fail atomic.Bool }

// newJobHandler wires a Handler against a fake PostgREST whose claim_message RPC
// returns claimStatus.
func newJobHandler(t *testing.T, claimStatus string) (*Handler, *hits) {
	t.Helper()
	h := &hits{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rpc/claim_message":
			h.claim.Store(true)
			_, _ = w.Write([]byte(`"` + claimStatus + `"`))
		case "/rpc/mark_done":
			h.done.Store(true)
		case "/rpc/mark_error":
			h.fail.Store(true)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	hd := New(repo.NewRepo(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})), nil)
	return hd, h
}

func TestHandleJob_AcquiredRunsAndMarksDone(t *testing.T) {
	hd, h := newJobHandler(t, repo.ClaimAcquired)
	if err := hd.handleJob(context.Background(), model.JobMsg{ID: "j1", Command: "x"}); err != nil {
		t.Fatalf("handleJob: %v", err)
	}
	if !h.claim.Load() || !h.done.Load() {
		t.Errorf("claim=%v done=%v, want both true", h.claim.Load(), h.done.Load())
	}
	if h.fail.Load() {
		t.Error("mark_error called on success, want not")
	}
}

func TestHandleJob_DoneSkips(t *testing.T) {
	hd, h := newJobHandler(t, repo.ClaimDone)
	if err := hd.handleJob(context.Background(), model.JobMsg{ID: "j1"}); err != nil {
		t.Fatalf("done should ack (nil), got: %v", err)
	}
	if h.done.Load() {
		t.Error("mark_done called on skip, want not")
	}
}

func TestHandleJob_LockedNaks(t *testing.T) {
	hd, _ := newJobHandler(t, repo.ClaimLocked)
	if err := hd.handleJob(context.Background(), model.JobMsg{ID: "j1"}); err == nil {
		t.Fatal("locked should return error so the bus naks")
	}
}
