package cluster_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestPickPlacementDomainSkipsRoutingOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/clusters" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"domain": "routing.thinkmay.net",
				"free":   999,
				"secret": json.RawMessage(`{}`),
			},
			{
				"domain": "haiphong.thinkmay.net",
				"free":   10,
				"secret": json.RawMessage(`{"url":"https://haiphong.thinkmay.net","username":"a","password":"b"}`),
			},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	domain, err := cluster.PickPlacementDomain(context.Background(), pr)
	if err != nil {
		t.Fatal(err)
	}
	if domain != "haiphong.thinkmay.net" {
		t.Fatalf("domain=%q", domain)
	}
}

func TestPickPlacementDomainNoEligibleCluster(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"domain": "routing.thinkmay.net", "free": 1, "secret": json.RawMessage(`{}`)},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	_, err := cluster.PickPlacementDomain(context.Background(), pr)
	if err == nil {
		t.Fatal("expected error")
	}
}
