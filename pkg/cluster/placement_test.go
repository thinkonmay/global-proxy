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

func TestPickPlacementDomainPrefersMostFree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/clusters" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"domain": "macro9.thinkmay.net", "free": 999},
			{"domain": "haiphong.thinkmay.net", "free": 10},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	domain, err := cluster.PickPlacementDomain(context.Background(), pr)
	if err != nil {
		t.Fatal(err)
	}
	if domain != "macro9.thinkmay.net" {
		t.Fatalf("domain=%q", domain)
	}
}

func TestPickPlacementDomainNoEligibleCluster(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"domain": "", "free": 1},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	_, err := cluster.PickPlacementDomain(context.Background(), pr)
	if err == nil {
		t.Fatal("expected error")
	}
}
