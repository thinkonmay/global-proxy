package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
)

func TestStaticIssuerRegistryRejectsUnknown(t *testing.T) {
	r := NewStaticIssuerRegistry(map[string]string{
		"haiphong.thinkmay.net": "https://haiphong.thinkmay.net",
	}, IssuerRegistryConfig{})

	_, err := r.FetchURL(context.Background(), "https://evil.example.com")
	if err != pocketbase.ErrUnknownIssuer {
		t.Fatalf("err = %v", err)
	}
}

func TestStaticIssuerRegistryHomeFetchOverride(t *testing.T) {
	r := NewStaticIssuerRegistry(map[string]string{
		"haiphong.thinkmay.net": "https://haiphong.thinkmay.net",
	}, IssuerRegistryConfig{
		HomeFetch:      "https://host.docker.internal",
		HomeIssuerHost: "https://haiphong.thinkmay.net",
	})

	got, err := r.FetchURL(context.Background(), "https://haiphong.thinkmay.net:443")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://host.docker.internal" {
		t.Fatalf("got %q", got)
	}
}

func TestIssuerRegistryLoadsActiveClusters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/clusters" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"id": 1, "domain": "haiphong.thinkmay.net", "active": true,
				"secret": map[string]string{
					"url": "https://pb-internal.example", "username": "a", "password": "b",
				},
			},
			{"id": 2, "domain": "inactive.example", "active": false},
		})
	}))
	t.Cleanup(srv.Close)

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	r := NewIssuerRegistry(pr, IssuerRegistryConfig{})

	got, err := r.FetchURL(context.Background(), "haiphong.thinkmay.net")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://pb-internal.example" {
		t.Fatalf("got %q", got)
	}
	_, err = r.FetchURL(context.Background(), "inactive.example")
	if err != pocketbase.ErrUnknownIssuer {
		t.Fatalf("inactive err = %v", err)
	}
}

func TestNormalizeHost(t *testing.T) {
	if got := NormalizeHost("https://Haiphong.Thinkmay.NET:443"); got != "haiphong.thinkmay.net" {
		t.Fatalf("got %q", got)
	}
}
