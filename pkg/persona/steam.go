package persona

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

func searchSteamStore(ctx context.Context, client *http.Client, name string) ([]steamSearchHit, error) {
	if client == nil {
		client = http.DefaultClient
	}
	u := "https://store.steampowered.com/api/storesearch/?term=" + url.QueryEscape(name) + "&cc=vn&l=english&count=5"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var data struct {
		Items []steamSearchHit `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data.Items, nil
}

type steamSearchHit struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// ResolveSteamAppID resolves a game title to a Steam App ID via storesearch.
func ResolveSteamAppID(ctx context.Context, client *http.Client, name string) (int64, bool) {
	hits, err := searchSteamStore(ctx, client, name)
	if err != nil || len(hits) == 0 {
		return 0, false
	}
	id, ok := bestSteamMatch(hits, name)
	if !ok || id <= 0 {
		return 0, false
	}
	return int64(id), true
}

func bestSteamMatch(hits []steamSearchHit, name string) (int, bool) {
	if len(hits) == 0 {
		return 0, false
	}
	needle := normalizeGameName(name)
	for _, hit := range hits {
		if normalizeGameName(hit.Name) == needle {
			return hit.ID, true
		}
	}
	return hits[0].ID, hits[0].ID > 0
}

func normalizeGameName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, suffix := range []string{".exe", "™", "®"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}
