package catalog_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/catalog"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestEnsureSteamStoreInsertsSlimPostgresRow(t *testing.T) {
	steam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"2711030": {
				"success": true,
				"data": {
					"steam_appid": 2711030,
					"name": "Sugardew Island",
					"header_image": "https://cdn.example/sugar.jpg",
					"short_description": "cozy farm shop",
					"genres": [{"description": "Simulation"}]
				}
			}
		}`))
	}))
	t.Cleanup(steam.Close)

	var inserted map[string]any
	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/stores"):
			_, _ = w.Write([]byte("[]"))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/stores"):
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &inserted)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(pr.Close)

	client := steam.Client()
	client.Transport = newRoundTripHost(steam.URL, client.Transport)

	if err := catalog.EnsureSteamStore(
		context.Background(),
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		client,
		nil,
		2711030,
	); err != nil {
		t.Fatal(err)
	}
	if inserted["name"] != "Sugardew Island" {
		t.Fatalf("inserted=%#v", inserted)
	}
	if inserted["header_image"] != "https://cdn.example/sugar.jpg" {
		t.Fatalf("inserted=%#v", inserted)
	}
	if _, ok := inserted["metadata"]; ok {
		t.Fatalf("metadata should not be stored in postgres: %#v", inserted)
	}
}

func TestEnsureSteamStoreSkipsWhenAlreadyEnriched(t *testing.T) {
	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		_, _ = w.Write([]byte(`[{
			"id": 123,
			"header_image":"https://cdn.example/existing.jpg"
		}]`))
	}))
	t.Cleanup(pr.Close)

	err := catalog.EnsureSteamStore(
		context.Background(),
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		nil,
		nil,
		123,
	)
	if err != nil {
		t.Fatal(err)
	}
}
