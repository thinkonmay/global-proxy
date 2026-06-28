package catalog_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/catalog"
)

func TestFetchSteamAppDetails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("appids") != "413150" {
			t.Fatalf("appids=%q", r.URL.Query().Get("appids"))
		}
		_, _ = w.Write([]byte(`{
			"413150": {
				"success": true,
				"data": {
					"steam_appid": 413150,
					"name": "Stardew Valley",
					"header_image": "https://cdn.example/header.jpg",
					"genres": [
						{"id": "23", "description": "Indie"},
						{"id": "28", "description": "Simulation"}
					]
				}
			}
		}`))
	}))
	t.Cleanup(srv.Close)

	client := srv.Client()
	client.Transport = newRoundTripHost(srv.URL, client.Transport)

	out, err := catalog.FetchSteamAppDetails(context.Background(), client, 413150)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != "Stardew Valley" {
		t.Fatalf("name=%q", out.Name)
	}
	genres := catalog.GenreDescriptions(out.Raw)
	if len(genres) != 2 || genres[0] != "Indie" {
		t.Fatalf("genres=%v", genres)
	}
}

func TestGenreDescriptionsEmpty(t *testing.T) {
	if got := catalog.GenreDescriptions(nil); len(got) != 0 {
		t.Fatalf("genres=%v", got)
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
