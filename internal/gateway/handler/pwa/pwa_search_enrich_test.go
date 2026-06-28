package pwa

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestResolveGameSteamIDFromName(t *testing.T) {
	steam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{"id": 1551360, "name": "Forza Horizon 5"},
			},
		})
	}))
	t.Cleanup(steam.Close)

	h := New(
		config.Config{LLM: config.LLM{BaseURL: "http://127.0.0.1:1", APIKey: "k", Model: "test"}},
		nil, rewriteHostTransport(steam.URL, nil), persona.New(nil, nil), nil, nil,
	)

	game := pwaGameSearch{Name: "Forza Horizon 5"}
	id := h.resolveGameSteamID(context.Background(), &game)
	if id != 1551360 {
		t.Fatalf("id=%d game=%+v", id, game)
	}
	if game.ID != 1551360 {
		t.Fatalf("game.ID=%d", game.ID)
	}
}

func TestResolveGameSteamIDKeepsExistingID(t *testing.T) {
	h := New(config.Config{}, nil, nil, persona.New(nil, nil), nil, nil)
	game := pwaGameSearch{ID: 42, Name: "Ignored"}
	if id := h.resolveGameSteamID(context.Background(), &game); id != 42 {
		t.Fatalf("id=%d", id)
	}
}

func TestEnrichSearchGamesResolvesMissingID(t *testing.T) {
	steam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "storesearch"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"id": 2711030, "name": "Sugardew Island"},
				},
			})
		case strings.Contains(r.URL.Path, "appdetails"):
			_, _ = w.Write([]byte(`{
				"2711030": {
					"success": true,
					"data": {
						"name": "Sugardew Island",
						"header_image": "https://cdn.example/sugar.jpg",
						"short_description": "cozy"
					}
				}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(steam.Close)

	var inserted bool
	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if inserted {
				_, _ = w.Write([]byte(`[{
					"id": 2711030,
					"name": "Sugardew Island",
					"header_image": "https://cdn.example/sugar.jpg",
					"short_description": "cozy"
				}]`))
				return
			}
			_, _ = w.Write([]byte("[]"))
		case http.MethodPost:
			inserted = true
			w.WriteHeader(http.StatusCreated)
			_, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(pr.Close)

	client := steam.Client()
	rt := rewriteHostTransport(steam.URL, client.Transport)

	h := New(
		config.Config{LLM: config.LLM{BaseURL: "http://127.0.0.1:1", APIKey: "k", Model: "test"}},
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		rt,
		persona.New(nil, nil),
		nil,
		nil,
	)

	games := []pwaGameSearch{{Name: "Sugardew Island", Reason: "cozy", Score: 0.9}}
	h.enrichSearchGames(context.Background(), games, nil)

	if games[0].ID != 2711030 {
		t.Fatalf("id=%d", games[0].ID)
	}
	if games[0].Info == nil || games[0].Info.HeaderImage != "https://cdn.example/sugar.jpg" {
		t.Fatalf("info=%#v inserted=%v", games[0].Info, inserted)
	}
}

func rewriteHostTransport(host string, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req = req.Clone(req.Context())
		req.URL.Scheme = "http"
		req.URL.Host = host
		return base.RoundTrip(req)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
