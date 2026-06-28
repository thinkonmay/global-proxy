package llmtrace

import (
	"testing"
)

func TestSummarizeCompletionToolCalls(t *testing.T) {
	raw := []byte(`{
		"choices": [{
			"finish_reason": "tool_calls",
			"message": {
				"content": "",
				"tool_calls": [
					{"function": {"name": "google_search"}},
					{"function": {"name": "search_steam"}}
				]
			}
		}]
	}`)
	s := SummarizeCompletion(raw)
	if s.FinishReason != "tool_calls" {
		t.Fatalf("finish_reason=%q", s.FinishReason)
	}
	if len(s.ToolCallNames) != 2 || s.ToolCallNames[0] != "google_search" {
		t.Fatalf("tools=%v", s.ToolCallNames)
	}
}

func TestTruncateString(t *testing.T) {
	got := TruncateString("abcdef", 3)
	if got != "abc…" {
		t.Fatalf("got=%q", got)
	}
}

func TestBodyMeta(t *testing.T) {
	model, msgs, tools := BodyMeta(map[string]any{
		"model":    "deepseek-v4-flash",
		"messages": []any{map[string]any{"role": "user"}},
		"tools":    []any{map[string]any{"type": "function"}},
	})
	if model != "deepseek-v4-flash" || msgs != 1 || tools != 1 {
		t.Fatalf("model=%q msgs=%d tools=%d", model, msgs, tools)
	}
}
