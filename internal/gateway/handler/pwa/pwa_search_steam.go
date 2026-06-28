package pwa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

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
	schemaJSON, _ := json.Marshal(pwaSearchResponseSchema())
	base := `You are a Game search engine
Your task is to analyze user persona and find games for the user.
Ensure returned games are available on Steam
Do google search if necessary

[Rules]
- If user enter a game's name, that game must be in number 1 of the list with highest score
- Score must be calculate based on similarity of the game, then user's persona
- CRITICAL: Once you found 3 to 5 matching games from Steam, STOP searching immediately and return the final JSON object. Do not endlessly call tools!

[User Persona]
`
	if persona != nil {
		base += fmt.Sprintf("\n- Objective: %s\n- Gamer Type: %s\n- Persona: %s", persona.Objective, persona.GamerType, persona.Persona)
	}
	base += "\n\nCRITICAL RULE: Return JSON matching this schema:\n" + string(schemaJSON)
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
