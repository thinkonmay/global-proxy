package serpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/serpapi"
)

func TestGoogleSearchReturnsOrganicResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "cozy farming games steam" {
			t.Fatalf("q=%q", r.URL.Query().Get("q"))
		}
		if r.URL.Query().Get("api_key") != "test-key" {
			t.Fatalf("api_key=%q", r.URL.Query().Get("api_key"))
		}
		_, _ = w.Write([]byte(`{
			"organic_results": [
				{"title":"Stardew Valley","link":"https://store.steampowered.com/app/413150","snippet":"farming sim"}
			]
		}`))
	}))
	t.Cleanup(srv.Close)

	c := serpapi.Client{
		HTTPClient: srv.Client(),
		APIKey:     "test-key",
		BaseURL:    srv.URL,
	}
	out, err := c.GoogleSearch(context.Background(), "cozy farming games steam")
	if err != nil {
		t.Fatal(err)
	}
	results, ok := out["results"].([]map[string]any)
	if !ok {
		t.Fatalf("results=%#v", out["results"])
	}
	if len(results) != 1 || results[0]["title"] != "Stardew Valley" {
		t.Fatalf("results=%#v", results)
	}
}

func TestGoogleSearchEmptyQuery(t *testing.T) {
	out, err := serpapi.GoogleSearch(context.Background(), nil, "key", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if arr, ok := out["results"].([]any); !ok || len(arr) != 0 {
		t.Fatalf("results=%#v", out["results"])
	}
}

func TestGoogleSearchMissingAPIKey(t *testing.T) {
	_, err := serpapi.GoogleSearch(context.Background(), nil, "", "test")
	if err == nil {
		t.Fatal("expected error")
	}
}
