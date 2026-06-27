package grants_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/grants"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestGrantBucketAccessRPCOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/grant_bucket_access_v1" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"bucket_name": "bucket-1"})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	cred, err := grants.GrantBucketAccess(context.Background(), pr, nil, "u@example.com", "test.thinkmay.net")
	if err != nil {
		t.Fatal(err)
	}
	if cred["bucket_name"] != "bucket-1" {
		t.Fatalf("cred: %v", cred)
	}
	if _, ok := cred["access_id"]; ok {
		t.Fatalf("expected no access_id without storj client: %v", cred)
	}
}

func TestGrantAndClaimApp(t *testing.T) {
	var grantCalls, claimCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/grant_app_access_v1"):
			grantCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{"app_id": "570"})
		case strings.HasSuffix(r.URL.Path, "/claim_v1"):
			claimCalls++
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":       int32(42),
				"username": "steam",
				"password": "secret",
				"depotKey": map[string]string{"1": "abc"},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	claim, err := grants.GrantAndClaimApp(context.Background(), pr, "u@example.com", "test.thinkmay.net", "570")
	if err != nil {
		t.Fatal(err)
	}
	if grantCalls != 1 || claimCalls != 1 {
		t.Fatalf("grant=%d claim=%d", grantCalls, claimCalls)
	}
	if claim.KeepaliveID != 42 || claim.Username != "steam" || claim.Password != "secret" {
		t.Fatalf("claim: %+v", claim)
	}
	if claim.DepotKey["1"] != "abc" {
		t.Fatalf("depot: %v", claim.DepotKey)
	}
}
