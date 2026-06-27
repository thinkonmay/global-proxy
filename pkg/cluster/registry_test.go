package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestFreeGBFromWorkerInfoJSON(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"Pools": []map[string]any{
			{"size": int64(0), "used": int64(0), "total": int64(3 * 1024 * 1024 * 1024)},
			{"size": int64(0), "used": int64(1024 * 1024 * 1024), "total": int64(2 * 1024 * 1024 * 1024)},
		},
	})
	gb, ok := FreeGBFromWorkerInfoJSON(body)
	if !ok || gb != 4 {
		t.Fatalf("FreeGBFromWorkerInfoJSON() = (%d, %v) want (4, true)", gb, ok)
	}
}

func TestRegisterCallsRPC(t *testing.T) {
	free := 12
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/rpc/register_cluster_v1") {
			t.Fatalf("path = %s", r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["p_domain"] != "haiphong.thinkmay.net" || payload["p_node"] != "macro9" {
			t.Fatalf("payload = %#v", payload)
		}
		if int(payload["p_free"].(float64)) != free {
			t.Fatalf("free = %#v", payload["p_free"])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	if err := Register(context.Background(), pr, "https://haiphong.thinkmay.net:443", "macro9", &free); err != nil {
		t.Fatal(err)
	}
}
