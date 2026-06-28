package pwa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/serpapi"
)

type pwaSearchRequest struct {
	Description string `json:"description"`
	Issuer      string `json:"issuer"`
}

type pwaGameSearch struct {
	ID     int           `json:"id"`
	Name   string        `json:"name"`
	Reason string        `json:"reason"`
	Score  float64       `json:"score"`
	Info   *pwaStoreGame `json:"info,omitempty"`
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
	Objective string `json:"objective"`
	GamerType string `json:"gamer_type"`
	Persona   string `json:"persona"`
}

func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	var req pwaSearchRequest
	if err := httpx.ReadJSONBody(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Description) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Missing description")
		return
	}
	if h.llm.BaseURL == "" || h.llm.APIKey == "" {
		httpx.WriteError(w, http.StatusServiceUnavailable, "search not configured")
		return
	}

	usr, code, msg := auth.PWAAuthFromRequest(r.Context(), h.transport, r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()

	persona, _ := h.fetchPersonaProfile(ctx, req.Issuer, r.Header.Get("Authorization"), usr.UserID)
	result, err := h.callLLMSearch(ctx, req.Description, persona)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if len(result.Games) == 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"suggestion": result.Suggestion, "games": []any{}})
		return
	}
	h.enrichSearchGames(ctx, result.Games)
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) fetchPersonaProfile(ctx context.Context, issuer, authHeader, uid string) (*pwaUserProfile, error) {
	if h.pr != nil && issuer != "" && authHeader != "" {
		usr, _, _ := auth.PWAAuthFromRequest(ctx, h.transport, &http.Request{
			Header: http.Header{"Authorization": []string{authHeader}},
		})
		if usr.Email != "" {
			profile, err := persona.FetchProfile(ctx, h.pr, strings.ToLower(usr.Email))
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
	fetchBase, code, msg := auth.ResolveClusterURL(ctx, issuer)
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

func (h *Handler) callLLMSearch(ctx context.Context, description string, persona *pwaUserProfile) (struct {
	Suggestion string          `json:"suggestion"`
	Games      []pwaGameSearch `json:"games"`
}, error) {
	var out struct {
		Suggestion string          `json:"suggestion"`
		Games      []pwaGameSearch `json:"games"`
	}

	system := pwaSearchSystemPrompt(persona)
	messages := []map[string]any{
		{"role": "system", "content": system},
		{"role": "user", "content": "Help me find game with following description: " + description},
	}
	tools := h.pwaSearchTools()

	for round := 0; round < 5; round++ {
		body := map[string]any{
			"model":    h.llm.Model,
			"messages": messages,
			"tools":    tools,
			// deepseek-v4-flash supports json_object but not json_schema.
			"response_format": map[string]any{"type": "json_object"},
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
				content, ok := h.runPWASearchTool(ctx, tc.Function.Name, tc.Function.Arguments)
				if !ok {
					continue
				}
				messages = append(messages, map[string]any{
					"role":         "tool",
					"tool_call_id": tc.ID,
					"content":      content,
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

func (h *Handler) pwaSearchTools() []map[string]any {
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
	if h.serpAPIKey != "" {
		tools = append(tools, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        "google_search",
				"description": "Search Google for game recommendations, reviews, and trending titles. Use before search_steam when the user describes a vibe, genre, or comparison rather than a specific game name.",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{"type": "string", "description": "Google search query"},
					},
					"required": []string{"query"},
				},
			},
		})
	}
	return tools
}

func (h *Handler) runPWASearchTool(ctx context.Context, name, arguments string) (string, bool) {
	switch {
	case strings.HasPrefix(name, "search_steam"):
		var args struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal([]byte(arguments), &args)
		result, _ := searchSteamStore(ctx, h.httpClient, args.Name)
		return mustJSONString(result), true
	case strings.HasPrefix(name, "google_search"):
		if h.serpAPIKey == "" {
			return mustJSONString(map[string]any{"results": []any{}}), true
		}
		var args struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal([]byte(arguments), &args)
		result, _ := serpapi.GoogleSearch(ctx, h.httpClient, h.serpAPIKey, args.Query)
		return mustJSONString(result), true
	default:
		return "", false
	}
}

func (h *Handler) llmChat(ctx context.Context, body map[string]any) ([]byte, error) {
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

func (h *Handler) enrichSearchGames(ctx context.Context, games []pwaGameSearch) {
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

func (h *Handler) searchStoreByID(ctx context.Context, id int64) (*pwaStoreGame, error) {
	var rows []pwaStoreGame
	if err := h.pr.RPC(ctx, "search_stores", map[string]any{"text": strconv.FormatInt(id, 10)}, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}
