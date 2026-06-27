package metricsagg

import (
	"bytes"
	"strings"
	"testing"
)

func TestInjectNodeLabel(t *testing.T) {
	tests := []struct {
		in   string
		node string
		want string
	}{
		{`go_goroutines 42`, "worker-a", `go_goroutines{node="worker-a"} 42`},
		{`cpu_usage{mode="idle"} 1.5`, "worker-a", `cpu_usage{node="worker-a",mode="idle"} 1.5`},
		{`cpu_usage{mode="idle"} 1.5 1710000000`, "worker-b", `cpu_usage{node="worker-b",mode="idle"} 1.5 1710000000`},
	}
	for _, tt := range tests {
		got, ok := injectNodeLabel([]byte(tt.in), tt.node)
		if !ok {
			t.Fatalf("injectNodeLabel(%q) failed", tt.in)
		}
		if string(got) != tt.want {
			t.Fatalf("injectNodeLabel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRelabelMetricsForNodeSkipsMetadata(t *testing.T) {
	body := []byte("# HELP go_goroutines ...\n# TYPE go_goroutines gauge\ngo_goroutines 7\n")
	got := relabelMetricsForNode(body, "macro9")
	if bytes.Contains(got, []byte("# HELP")) {
		t.Fatalf("metadata leaked: %s", got)
	}
	if !bytes.Contains(got, []byte(`go_goroutines{node="macro9"} 7`)) {
		t.Fatalf("missing relabeled sample: %s", got)
	}
}

func TestBuildExpositionUniqueLabelSets(t *testing.T) {
	body := buildExposition([]NodeSnapshot{
		{Node: "worker-a", Body: []byte("go_goroutines 10\n")},
		{Node: "worker-b", Body: []byte("go_goroutines 20\n")},
	})
	lines := strings.Split(string(body), "\n")
	seen := make(map[string]int)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "thinkmay_") {
			continue
		}
		seen[line]++
	}
	for line, n := range seen {
		if n > 1 {
			t.Fatalf("duplicate sample line %q appears %d times", line, n)
		}
	}
	if !strings.Contains(string(body), `go_goroutines{node="worker-a"} 10`) {
		t.Fatalf("missing worker-a series: %s", body)
	}
	if !strings.Contains(string(body), `go_goroutines{node="worker-b"} 20`) {
		t.Fatalf("missing worker-b series: %s", body)
	}
}
