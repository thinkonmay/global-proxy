package catalog_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/catalog"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestResolveStoreSyncFallbackWhenWorkerIdle(t *testing.T) {
	steam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"413150": {
				"success": true,
				"data": {
					"name": "Civilization VI",
					"header_image": "https://cdn.example/civ6.jpg",
					"short_description": "strategy"
				}
			}
		}`))
	}))
	t.Cleanup(steam.Close)

	var inserted bool
	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/stores"):
			if inserted {
				_, _ = w.Write([]byte(`[{
					"id": 413150,
					"name": "Civilization VI",
					"header_image": "https://cdn.example/civ6.jpg",
					"short_description": "strategy"
				}]`))
				return
			}
			_, _ = w.Write([]byte("[]"))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/stores"):
			inserted = true
			w.WriteHeader(http.StatusCreated)
			_, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(pr.Close)

	b := busmemory.New(nil)
	// Subscribe but do not process jobs — simulates worker offline / slow.
	bus.Subscribe(b, model.TopicCatalogStoreJob, "noop", func(_ context.Context, _ model.CatalogStoreJobMsg) error {
		return nil
	})

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req = req.Clone(req.Context())
			req.URL.Scheme = "http"
			req.URL.Host = strings.TrimPrefix(strings.TrimPrefix(steam.URL, "https://"), "http://")
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	rec, err := catalog.ResolveStore(context.Background(), catalog.StoreDeps{
		PostgREST: postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		SteamHTTP: client,
		Bus:       b,
	}, 413150)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("expected sync EnsureSteamStore insert after worker wait")
	}
	if rec == nil || rec.ID != 413150 {
		t.Fatalf("rec=%#v", rec)
	}
	if rec.HeaderImage != "https://cdn.example/civ6.jpg" {
		t.Fatalf("rec=%#v", rec)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
