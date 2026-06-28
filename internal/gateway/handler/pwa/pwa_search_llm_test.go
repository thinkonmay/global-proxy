package pwa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestAssistantMessageTextPrefersContent(t *testing.T) {
	content := "hello"
	reason := "reasoning"
	got := assistantMessageText(pwaLLMMessage{
		Content:          &content,
		ReasoningContent: &reason,
	})
	if got != "hello" {
		t.Fatalf("got=%q", got)
	}
}

func TestAssistantMessageTextUsesReasoningFallback(t *testing.T) {
	empty := ""
	reason := `{"suggestion":"Try these","games":[]}`
	got := assistantMessageText(pwaLLMMessage{
		Content:          &empty,
		ReasoningContent: &reason,
	})
	if got != reason {
		t.Fatalf("got=%q", got)
	}
}

func TestCallLLMSearchFinalizesAfterToolRoundBudget(t *testing.T) {
	var calls atomic.Int32
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		var req struct {
			Messages []map[string]any `json:"messages"`
			Tools    []any            `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		if len(req.Tools) == 0 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{{
					"finish_reason": "stop",
					"message": map[string]any{
						"content": `{"suggestion":"Racing picks","games":[{"id":440,"name":"Team Fortress 2","reason":"fast","score":0.9}]}`,
					},
				}},
			})
			return
		}

		if n <= int32(pwaSearchMaxToolRounds) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{{
					"finish_reason": "tool_calls",
					"message": map[string]any{
						"tool_calls": []map[string]any{{
							"id":   "tc1",
							"type": "function",
							"function": map[string]any{
								"name":      "search_steam",
								"arguments": `{"name":"racing game"}`,
							},
						}},
					},
				}},
			})
			return
		}
		t.Fatalf("unexpected extra llm call %d", n)
	}))
	t.Cleanup(llm.Close)

	h := New(config.Config{
		LLM: config.LLM{BaseURL: llm.URL + "/v1", APIKey: "k", Model: "test"},
	}, nil, nil, nil, nil, nil)

	out, err := h.callLLMSearch(context.Background(), "racing games", nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Suggestion != "Racing picks" {
		t.Fatalf("suggestion=%q", out.Suggestion)
	}
	if len(out.Games) != 1 || out.Games[0].ID != 440 {
		t.Fatalf("games=%+v", out.Games)
	}
	if calls.Load() != int32(pwaSearchMaxToolRounds)+1 {
		t.Fatalf("calls=%d want %d", calls.Load(), pwaSearchMaxToolRounds+1)
	}
}

func TestParsePWASearchResponseExtractsJSONFence(t *testing.T) {
	var out struct {
		Suggestion string          `json:"suggestion"`
		Games      []pwaGameSearch `json:"games"`
	}
	err := parsePWASearchResponse("```json\n"+`{"suggestion":"ok","games":[]}`+"\n```", &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.Suggestion != "ok" {
		t.Fatalf("suggestion=%q", out.Suggestion)
	}
}

func TestPwaSearchSystemPromptMentionsToolBudget(t *testing.T) {
	prompt := pwaSearchSystemPrompt(nil)
	for _, needle := range []string{"google_search at most once", "3 to 5 games", "stop calling tools"} {
		if !strings.Contains(prompt, needle) {
			t.Fatalf("prompt missing %q", needle)
		}
	}
}
