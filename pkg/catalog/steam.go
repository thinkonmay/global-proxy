package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const steamAppDetailsURL = "https://store.steampowered.com/api/appdetails"

// SteamAppDetails is the Steam Store appdetails "data" object.
type SteamAppDetails struct {
	Name string
	Raw  map[string]any
}

// FetchSteamAppDetails loads Steam Store metadata for a Steam App ID.
func FetchSteamAppDetails(ctx context.Context, client *http.Client, appID int64) (*SteamAppDetails, error) {
	if appID <= 0 {
		return nil, fmt.Errorf("invalid steam app id")
	}
	if client == nil {
		client = http.DefaultClient
	}

	params := url.Values{}
	params.Set("appids", fmt.Sprintf("%d", appID))
	params.Set("cc", "us")
	params.Set("l", "english")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, steamAppDetailsURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("steam appdetails: status %d", resp.StatusCode)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	entry, ok := payload[fmt.Sprintf("%d", appID)]
	if !ok {
		return nil, fmt.Errorf("steam appdetails: missing app %d", appID)
	}

	var wrapper struct {
		Success bool           `json:"success"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal(entry, &wrapper); err != nil {
		return nil, err
	}
	if !wrapper.Success || wrapper.Data == nil {
		return nil, fmt.Errorf("steam appdetails: app %d not found", appID)
	}

	name, _ := wrapper.Data["name"].(string)
	return &SteamAppDetails{Name: strings.TrimSpace(name), Raw: wrapper.Data}, nil
}

// GenreDescriptions extracts genre labels from Steam appdetails metadata.
func GenreDescriptions(metadata map[string]any) []string {
	raw, ok := metadata["genres"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		desc, _ := m["description"].(string)
		desc = strings.TrimSpace(desc)
		if desc != "" {
			out = append(out, desc)
		}
	}
	return out
}

func storeRowFromSteam(appID int64, details *SteamAppDetails) map[string]any {
	row := map[string]any{
		"id":   appID,
		"type": "STEAM",
	}
	if details == nil {
		return row
	}
	if details.Name != "" {
		row["name"] = details.Name
	}
	if details.Raw != nil {
		if v, ok := details.Raw["header_image"].(string); ok && strings.TrimSpace(v) != "" {
			row["header_image"] = v
		}
		if v, ok := details.Raw["short_description"].(string); ok && strings.TrimSpace(v) != "" {
			row["short_description"] = v
		}
		if genres := GenreDescriptions(details.Raw); len(genres) > 0 {
			row["genres"] = genres
		}
	}
	return row
}
