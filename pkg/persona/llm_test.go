package persona_test

import (
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/persona"
)

func TestLLMPromptUsesPlatformAppUsageCDP2(t *testing.T) {
	prompt := persona.AnalystSystemPromptForTest()
	for _, want := range []string{
		"platform ClickHouse rollups",
		"app_key",
		"duration_sec",
		"launch_count",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q", want)
		}
	}
	for _, banned := range []string{"Rybbit", "rybbit", "custom_event", "session YAML"} {
		if strings.Contains(prompt, banned) {
			t.Fatalf("prompt must not reference %q", banned)
		}
	}
}
