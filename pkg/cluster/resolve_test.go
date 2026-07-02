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

func TestResolveGrantDomainByVolume(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user_v2":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"cluster_id": 3, "volume_id": "vol-1"},
			})
		case "/clusters":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 3, "domain": "haiphong.thinkmay.net"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	domain, err := cluster.ResolveGrantDomain(context.Background(), pr, "u@example.com", "vol-1")
	if err != nil {
		t.Fatal(err)
	}
	if domain != "haiphong.thinkmay.net" {
		t.Fatalf("domain=%q", domain)
	}
}

// With no volume specified, resolution falls back to the user's sole cluster
// (machines no longer carry a cluster, so there is no subscription-cluster path).
func TestResolveGrantDomainFromPrimaryCluster(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user_v2":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"cluster_id": 5, "volume_id": "vol-x"},
			})
		case "/clusters":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 5, "domain": "saigon2.thinkmay.net"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	domain, err := cluster.ResolveGrantDomain(context.Background(), pr, "u@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if domain != "saigon2.thinkmay.net" {
		t.Fatalf("domain=%q", domain)
	}
}
