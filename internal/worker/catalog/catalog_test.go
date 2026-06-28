package catalog_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	catalogworker "github.com/thinkonmay/global-proxy/api/internal/worker/catalog"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestCatalogStoreWorkerEnrichesOnBus(t *testing.T) {
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

	steamClient := steam.Client()
	steamClient.Transport = newRoundTripHost(steam.URL, steamClient.Transport)

	b := busmemory.New(nil)
	h := catalogworker.New(
		idempotency.New(idempotency.NewMemStore()),
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		steamClient,
		nil,
	)
	h.Init(b)

	if err := bus.Publish(context.Background(), b, model.TopicCatalogStoreJob, model.CatalogStoreJobMsg{
		RequestID: "catalog-store-2711030",
		AppID:     2711030,
		Type:      "STEAM",
	}); err != nil {
		t.Fatal(err)
	}
	b.Wait()

	deadline := time.Now().Add(2 * time.Second)
	for inserted == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if inserted == nil {
		t.Fatal("expected postgres insert")
	}
	if inserted["name"] != "Sugardew Island" {
		t.Fatalf("inserted=%#v", inserted)
	}
}

type roundTripHost struct {
	base      string
	transport http.RoundTripper
}

func newRoundTripHost(base string, transport http.RoundTripper) roundTripHost {
	return roundTripHost{base: base, transport: transport}
}

func (r roundTripHost) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = r.base[len("http://"):]
	if r.transport == nil {
		r.transport = http.DefaultTransport
	}
	return r.transport.RoundTrip(req)
}
