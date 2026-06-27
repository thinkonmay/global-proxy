package superuser_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/superuser"
)

func TestIsEmail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/is_superuser_email_v1") {
			http.NotFound(w, r)
			return
		}
		var args map[string]any
		_ = json.NewDecoder(r.Body).Decode(&args)
		if args["p_email"] != "ops@thinkmay.net" {
			_ = json.NewEncoder(w).Encode(false)
			return
		}
		_ = json.NewEncoder(w).Encode(true)
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	ok, err := superuser.IsEmail(context.Background(), pr, "ops@thinkmay.net")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected superuser")
	}
	ok, err = superuser.IsEmail(context.Background(), pr, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected non-superuser")
	}
}
