package cdp_test

import (
	"testing"
	"time"

	cdprollup "github.com/thinkonmay/global-proxy/api/pkg/cdp"
)

func TestBuildFrontendRollupCDP3b(t *testing.T) {
	synced := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	last := synced.Add(-2 * time.Hour)
	out := cdprollup.BuildFrontendRollup(30, 12, 3, 4, []string{"/store"}, []string{"page_entry"}, last, synced)
	if out.LookbackDays != 30 || out.Pageviews != 12 || out.Sessions != 4 {
		t.Fatalf("unexpected rollup: %+v", out)
	}
	if out.LastSeen == "" || out.SyncedAt == "" {
		t.Fatal("expected timestamps")
	}
	if len(out.TopPaths) != 1 {
		t.Fatalf("top_paths = %v", out.TopPaths)
	}
}
