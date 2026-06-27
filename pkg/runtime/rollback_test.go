package runtime_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	runtimepkg "github.com/thinkonmay/global-proxy/api/pkg/runtime"
)

func TestRollbackLeasesUnclaimsAppAndBucket(t *testing.T) {
	var calls []int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/unclaim_v1") {
			http.NotFound(w, r)
			return
		}
		var args map[string]any
		_ = json.NewDecoder(r.Body).Decode(&args)
		if id, ok := args["keepaliveid"].(float64); ok {
			calls = append(calls, int32(id))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	session := &persistent.WorkerSession{
		App: &persistent.AppSession{
			Keepalive: &persistent.Keepalive{KeepaliveID: 11},
		},
		S3Bucket: &persistent.S3Bucket{
			Keepalive: &persistent.Keepalive{KeepaliveID: 22},
		},
	}
	runtimepkg.RollbackLeases(context.Background(), pr, session)

	if len(calls) != 2 {
		t.Fatalf("calls = %v", calls)
	}
	if calls[0] != 11 || calls[1] != 22 {
		t.Fatalf("unexpected ids: %v", calls)
	}
}
