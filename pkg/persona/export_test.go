package persona

// Test exports for persona_test.

func NormalizeGameNameForTest(s string) string { return normalizeGameName(s) }

type SteamHitForTest = steamSearchHit

func BestSteamMatchForTest(hits []SteamHitForTest, name string) (int, bool) {
	return bestSteamMatch(hits, name)
}

func ResponseSchemaForTest() map[string]any { return personaResponseSchema() }
