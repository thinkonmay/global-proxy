package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/persona"
)

type pwaSearchRequest struct {
	Description string `json:"description"`
	Issuer      string `json:"issuer"`
}

type pwaGameSearch struct {
	ID     int            `json:"id"`
	Name   string         `json:"name"`
	Reason string         `json:"reason"`
	Score  float64        `json:"score"`
	Info   *pwaStoreGame  `json:"info,omitempty"`
}

type pwaStoreGame struct {
	ID               int64    `json:"id"`
	Name             string   `json:"name"`
	CodeName         string   `json:"code_name"`
	ShortDescription string   `json:"short_description"`
	HeaderImage      string   `json:"header_image"`
	Genres           []string `json:"genres"`
	Type             string   `json:"type"`
	Rank             float64  `json:"rank"`
}

type pwaUserProfile struct {
	Objective  string `json:"objective"`
	GamerType  string `json:"gamer_type"`
	Persona    string `json:"persona"`
}

func (h *PWAHandler) Search(w http.ResponseWriter, r *http.Request) {
	var req pwaSearchRequest
	if err := readJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Description) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing description"})
		return
	}
	if h.llm.BaseURL == "" || h.llm.APIKey == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "search not configured"})
		return
	}

	auth, code, msg := pwaAuthFromRequest(r.Context(), h.transport, r, req.Issuer)
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()

	persona, _ := h.fetchPersonaProfile(ctx, req.Issuer, r.Header.Get("Authorization"), auth.UserID)
	result, err := h.callLLMSearch(ctx, req.Description, persona)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}
	if len(result.Games) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"suggestion": result.Suggestion, "games": []any{}})
		return
	}
	h.enrichSearchGames(ctx, result.Games)
	writeJSON(w, http.StatusOK, result)
}

func (h *PWAHandler) fetchPersonaProfile(ctx context.Context, issuer, authHeader, uid string) (*pwaUserProfile, error) {
	if h.pr != nil && issuer != "" && authHeader != "" {
		auth, _, _ := pwaAuthFromRequest(ctx, h.transport, &http.Request{
			Header: http.Header{"Authorization": []string{authHeader}},
		}, issuer)
		if auth.Email != "" {
			profile, err := persona.FetchProfile(ctx, h.pr, strings.ToLower(auth.Email))
			if err == nil && profile != nil {
				var out pwaUserProfile
				if json.Unmarshal(profile, &out) == nil {
					return &out, nil
				}
			}
		}
	}
	if issuer == "" || uid == "" {
		return nil, nil
	}
	fetchBase, code, msg := resolveClusterURL(ctx, issuer)
	if code != 0 {
		return nil, fmt.Errorf("%s", msg)
	}
	u := strings.TrimRight(fetchBase, "/") + "/api/collections/persona/records?" + url.Values{
		"filter":  {fmt.Sprintf(`user=%q`, uid)},
		"perPage": {"1"},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authHeader)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("persona status %d", resp.StatusCode)
	}
	var page struct {
		Items []struct {
			Profile json.RawMessage `json:"profile"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || len(page.Items) == 0 {
		return nil, err
	}
	var profile pwaUserProfile
	if err := json.Unmarshal(page.Items[0].Profile, &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (h *PWAHandler) callLLMSearch(ctx context.Context, description string, persona *pwaUserProfile) (struct {
	Suggestion string          `json:"suggestion"`
	Games      []pwaGameSearch   `json:"games"`
}, error) {
	var out struct {
		Suggestion string          `json:"suggestion"`
		Games      []pwaGameSearch   `json:"games"`
	}

	system := pwaSearchSystemPrompt(persona)
	messages := []map[string]any{
		{"role": "system", "content": system},
		{"role": "user", "content": "Help me find game with following description: " + description},
	}
	tools := []map[string]any{{
		"type": "function",
		"function": map[string]any{
			"name":        "search_steam",
			"description": "Search Steam Store by game name. Returns top matching games with their Steam App ID.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "description": "Game name to search on Steam"},
				},
				"required": []string{"name"},
			},
		},
	}}

	for round := 0; round < 5; round++ {
		body := map[string]any{
			"model":    h.llm.Model,
			"messages": messages,
			"tools":    tools,
			"response_format": map[string]any{
				"type": "json_schema",
				"json_schema": map[string]any{
					"name":   "search_result",
					"schema": pwaSearchResponseSchema(),
					"strict": false,
				},
			},
		}
		raw, err := h.llmChat(ctx, body)
		if err != nil {
			return out, err
		}
		var completion struct {
			Choices []struct {
				FinishReason string `json:"finish_reason"`
				Message      struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(raw, &completion); err != nil {
			return out, err
		}
		if len(completion.Choices) == 0 {
			return out, fmt.Errorf("empty llm response")
		}
		choice := completion.Choices[0]
		if choice.FinishReason == "tool_calls" && len(choice.Message.ToolCalls) > 0 {
			messages = append(messages, map[string]any{
				"role":       "assistant",
				"content":    choice.Message.Content,
				"tool_calls": choice.Message.ToolCalls,
			})
			for _, tc := range choice.Message.ToolCalls {
				if !strings.HasPrefix(tc.Function.Name, "search_steam") {
					continue
				}
				var args struct {
					Name string `json:"name"`
				}
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
				result, _ := searchSteamStore(ctx, h.httpClient, args.Name)
				messages = append(messages, map[string]any{
					"role":         "tool",
					"tool_call_id": tc.ID,
					"content":      mustJSONString(result),
				})
			}
			continue
		}
		text := ""
		if choice.Message.Content != nil {
			text = strings.TrimSpace(*choice.Message.Content)
		}
		if text == "" {
			return out, fmt.Errorf("empty llm content")
		}
		text = extractJSONBlob(text)
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			return out, err
		}
		return out, nil
	}
	return out, fmt.Errorf("too many tool call rounds")
}

func (h *PWAHandler) llmChat(ctx context.Context, body map[string]any) ([]byte, error) {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(h.llm.BaseURL, "/")+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.llm.APIKey)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm: %s", data)
	}
	return data, nil
}

func (h *PWAHandler) enrichSearchGames(ctx context.Context, games []pwaGameSearch) {
	for i := range games {
		id := games[i].ID
		if id <= 0 {
			continue
		}
		info, err := h.searchStoreByID(ctx, int64(id))
		if err != nil || info == nil || info.ID != int64(id) {
			_ = h.pr.Insert(ctx, "stores", map[string]any{"id": id, "type": "STEAM"}, nil)
			info, _ = h.searchStoreByID(ctx, int64(id))
		}
		if info != nil {
			games[i].Info = info
		}
	}
}

func (h *PWAHandler) searchStoreByID(ctx context.Context, id int64) (*pwaStoreGame, error) {
	var rows []pwaStoreGame
	if err := h.pr.RPC(ctx, "search_stores", map[string]any{"text": strconv.FormatInt(id, 10)}, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

func searchSteamStore(ctx context.Context, client *http.Client, name string) (map[string]any, error) {
	u := "https://store.steampowered.com/api/storesearch/?term=" + url.QueryEscape(name) + "&cc=vn&l=english&count=5"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return map[string]any{"results": []any{}}, nil
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return map[string]any{"results": []any{}}, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var data struct {
		Items []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return map[string]any{"results": []any{}}, nil
	}
	results := make([]map[string]any, 0, len(data.Items))
	for _, item := range data.Items {
		results = append(results, map[string]any{"id": item.ID, "name": item.Name})
	}
	return map[string]any{"results": results}, nil
}

func pwaSearchSystemPrompt(persona *pwaUserProfile) string {
	base := `You are a Game search engine
Your task is to analyze user persona and find games for the user.
Ensure returned games are available on Steam
Do google search if necessary

[Rules]
- If user enter a game's name, that game must be in number 1 of the list with highest score
- Score must be calculate based on similarity of the game, then user's persona
- CRITICAL: Once you found 3 to 5 matching games from Steam, STOP searching immediately and return the final JSON schema. Do not endlessly call tools!

[User Persona]
`
	if persona != nil {
		base += fmt.Sprintf("\n- Objective: %s\n- Gamer Type: %s\n- Persona: %s", persona.Objective, persona.GamerType, persona.Persona)
	}
	base += "\n\nCRITICAL RULE: You MUST return your final response strictly matching the JSON schema."
	return base
}

func pwaSearchResponseSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"suggestion": map[string]any{"type": "string"},
			"games": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":   map[string]any{"type": "string"},
						"reason": map[string]any{"type": "string"},
						"score":  map[string]any{"type": "number"},
						"id":     map[string]any{"type": "integer"},
					},
					"required": []string{"name", "reason", "score", "id"},
				},
			},
		},
		"required": []string{"suggestion", "games"},
	}
}

var jsonFenceRe = regexp.MustCompile("(?s)```(?:json)?\\n?(.*?)\\n?```")

func extractJSONBlob(text string) string {
	if m := jsonFenceRe.FindStringSubmatch(text); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	first := strings.Index(text, "{")
	last := strings.LastIndex(text, "}")
	if first >= 0 && last > first {
		return text[first : last+1]
	}
	return text
}

func mustJSONString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
