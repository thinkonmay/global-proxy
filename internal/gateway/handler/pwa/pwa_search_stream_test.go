package pwa

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

type sseRecorder struct {
	*httptest.ResponseRecorder
}

func (s *sseRecorder) Flush() {}

func TestSearchSSEProgressAndResult(t *testing.T) {
	var llmCalls int
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls++
		if llmCalls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{{
					"finish_reason": "tool_calls",
					"message": map[string]any{
						"tool_calls": []map[string]any{{
							"id":   "tc1",
							"type": "function",
							"function": map[string]any{
								"name":      "search_steam",
								"arguments": `{"name":"Forza Horizon"}`,
							},
						}},
					},
				}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"finish_reason": "stop",
				"message": map[string]any{
					"content": `{"suggestion":"Try these racers","games":[{"id":1551360,"name":"Forza Horizon 5","reason":"open world racing","score":0.95}]}`,
				},
			}},
		})
	}))
	t.Cleanup(llm.Close)

	auth.ConfigureGoTrueAuth("test-secret")
	t.Cleanup(func() { auth.ConfigureGoTrueAuth("") })

	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/search_stores":
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(pr.Close)

	h := New(
		config.Config{LLM: config.LLM{BaseURL: llm.URL + "/v1", APIKey: "k", Model: "test"}},
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		nil,
		persona.New(postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}), nil), nil,
		nil,
	)
	mux := http.NewServeMux()
	h.Register(mux)

	body := bytes.NewBufferString(`{"description":"racing games"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/search/ai", body)
	req.Header.Set("Authorization", "Bearer "+testJWT(t))
	req.Header.Set("Accept", "text/event-stream")

	rec := &sseRecorder{ResponseRecorder: httptest.NewRecorder()}
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content-type=%q", ct)
	}

	var phases []string
	var gotResult bool
	sc := bufio.NewScanner(rec.Body)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		raw := strings.TrimPrefix(line, "data:")
		var evt pwaSearchSSEEvent
		if err := json.Unmarshal([]byte(raw), &evt); err != nil {
			t.Fatalf("event json: %v raw=%q", err, raw)
		}
		switch evt.Type {
		case "progress":
			phases = append(phases, evt.Phase)
		case "result":
			gotResult = true
			if evt.Suggestion != "Try these racers" {
				t.Fatalf("suggestion=%q", evt.Suggestion)
			}
			if len(evt.Games) != 1 {
				t.Fatalf("games=%+v", evt.Games)
			}
		case "error":
			t.Fatalf("unexpected error event: %+v", evt)
		}
	}
	if !gotResult {
		t.Fatal("missing result event")
	}
	if len(phases) == 0 {
		t.Fatalf("expected progress phases, body=%s", rec.Body.String())
	}
}