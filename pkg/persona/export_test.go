package persona

import (
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

// Test exports for persona_test.

func NormalizeGameNameForTest(s string) string { return normalizeGameName(s) }

type SteamHitForTest = steamSearchHit

func BestSteamMatchForTest(hits []SteamHitForTest, name string) (int, bool) {
	return bestSteamMatch(hits, name)
}

func ResponseSchemaForTest() map[string]any { return personaResponseSchema() }

func AnalystSystemPromptForTest() string { return analystSystemPrompt }

func TrimAppUsageForTest(apps []usage.AppUsageEntry, maxItems int) []usage.AppUsageEntry {
	return trimAppUsage(apps, maxItems)
}

func BuildCDPSignalsForTest(days int, apps []usage.AppUsageEntry, payments []PaymentRecord, subs []SubscriptionRecord, engagement EngagementContext, frontend FrontendContext) CDPSignals {
	return buildCDPSignals(days, apps, payments, subs, engagement, frontend)
}

type EngagementContextForTest = EngagementContext
