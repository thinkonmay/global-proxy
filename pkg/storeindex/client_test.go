package storeindex_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
)

func TestIndexAndSearchStore(t *testing.T) {
	var indexed storeindex.Document
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&indexed)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"result":"created"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/catalog-stores/_search":
			_, _ = w.Write([]byte(`{
				"hits": {
					"hits": [{
						"_score": 3.5,
						"_source": {
							"id": 413150,
							"name": "Stardew Valley",
							"header_image": "https://cdn.example/h.jpg",
							"short_description": "farming sim",
							"genres": ["Indie"],
							"type": "STEAM",
							"metadata": {"name":"Stardew Valley"}
						}
					}]
				}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c := storeindex.NewClient(srv.URL, "catalog-stores")
	doc := storeindex.DocumentFromSteam(413150, "Stardew Valley", []string{"Indie"}, map[string]any{
		"name":             "Stardew Valley",
		"header_image":     "https://cdn.example/h.jpg",
		"short_description": "farming sim",
	})
	if err := c.Index(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	if indexed.ID != 413150 {
		t.Fatalf("indexed=%#v", indexed)
	}

	hits, err := c.Search(context.Background(), "stardew", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Name != "Stardew Valley" {
		t.Fatalf("hits=%#v", hits)
	}
	if hits[0].HeaderImage == "" {
		t.Fatalf("hits=%#v", hits)
	}
}
