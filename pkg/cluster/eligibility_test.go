package cluster_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestUserEligibleForRuntimeStreamWithVolume(t *testing.T) {
	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/rpc/get_subscription_v3") {
			t.Fatal("subscription RPC should not run when volumes exist")
		}
		_, _ = w.Write([]byte(`[{"cluster_id":1,"volume_id":"vol-1"}]`))
	}))
	t.Cleanup(pr.Close)

	ok, err := cluster.UserEligibleForRuntimeStream(
		context.Background(),
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		"user@example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected eligible with volume")
	}
}

func TestUserEligibleForRuntimeStreamWithSubscriptionOnly(t *testing.T) {
	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/user_v2"):
			_, _ = w.Write([]byte("[]"))
		case strings.Contains(r.URL.Path, "/rpc/get_subscription_v3"):
			_, _ = w.Write([]byte(`[{"cluster":"haiphong.thinkmay.net"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(pr.Close)

	ok, err := cluster.UserEligibleForRuntimeStream(
		context.Background(),
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		"user@example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected eligible with subscription")
	}
}

func TestUserEligibleForRuntimeStreamNeither(t *testing.T) {
	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/user_v2"):
			_, _ = w.Write([]byte("[]"))
		case strings.Contains(r.URL.Path, "/rpc/get_subscription_v3"):
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(pr.Close)

	ok, err := cluster.UserEligibleForRuntimeStream(
		context.Background(),
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		"user@example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected ineligible without subscription or volume")
	}
}
