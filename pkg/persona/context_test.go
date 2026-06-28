package persona_test

import (
	"encoding/json"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

func TestTrimAppUsageCDP3(t *testing.T) {
	apps := make([]usage.AppUsageEntry, 5)
	for i := range apps {
		apps[i].AppKey = "game:test"
	}
	trimmed := persona.TrimAppUsageForTest(apps, 3)
	if len(trimmed) != 3 {
		t.Fatalf("got %d items, want 3", len(trimmed))
	}
	if persona.TrimAppUsageForTest(apps, 0) == nil || len(persona.TrimAppUsageForTest(apps, 0)) != 5 {
		t.Fatal("zero max should keep all items via default cap")
	}
}

func TestBuildCDPSignalsDefaultsCDP3(t *testing.T) {
	signals := persona.BuildCDPSignalsForTest(30, nil, nil, nil, persona.EngagementContext{}, persona.FrontendContext{
		Rollup:          json.RawMessage("{}"),
		RecentWebEvents: json.RawMessage("[]"),
	})
	if signals.AppUsageDays != 30 {
		t.Fatalf("app_usage_days = %d", signals.AppUsageDays)
	}
	if signals.Payments == nil || signals.Subscriptions == nil {
		t.Fatal("expected non-nil empty slices for payments and subscriptions")
	}
	if signals.Engagement.Feedbacks.Recent == nil {
		t.Fatal("expected non-nil recent feedback slice")
	}
	if len(signals.Payments) != 0 || len(signals.Subscriptions) != 0 {
		t.Fatal("expected empty slices")
	}
}
