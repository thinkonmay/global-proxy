package serpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const defaultSearchEndpoint = "https://serpapi.com/search.json"

// Client calls SerpApi Google organic search.
type Client struct {
	HTTPClient *http.Client
	APIKey     string
	// BaseURL overrides the search endpoint (tests only).
	BaseURL string
}

// GoogleSearch runs a Google organic search and returns compact results for LLM tools.
func GoogleSearch(ctx context.Context, client *http.Client, apiKey, query string) (map[string]any, error) {
	return Client{HTTPClient: client, APIKey: apiKey}.GoogleSearch(ctx, query)
}

func (c Client) GoogleSearch(ctx context.Context, query string) (map[string]any, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return map[string]any{"results": []any{}}, nil
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return map[string]any{"results": []any{}}, fmt.Errorf("serpapi not configured")
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	endpoint := strings.TrimSpace(c.BaseURL)
	if endpoint == "" {
		endpoint = defaultSearchEndpoint
	}

	params := url.Values{}
	params.Set("engine", "google")
	params.Set("q", query)
	params.Set("api_key", c.APIKey)
	params.Set("num", "5")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return map[string]any{"results": []any{}}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return map[string]any{"results": []any{}}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return map[string]any{"results": []any{}, "error": strings.TrimSpace(string(body))}, nil
	}

	var payload struct {
		OrganicResults []struct {
			Title   string `json:"title"`
			Link    string `json:"link"`
			Snippet string `json:"snippet"`
		} `json:"organic_results"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return map[string]any{"results": []any{}}, nil
	}

	results := make([]map[string]any, 0, len(payload.OrganicResults))
	for _, item := range payload.OrganicResults {
		results = append(results, map[string]any{
			"title":   item.Title,
			"link":    item.Link,
			"snippet": item.Snippet,
		})
	}
	return map[string]any{"results": results}, nil
}
