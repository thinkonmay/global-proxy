package gamification

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/testsupport"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestGamificationLeaderboardPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_star_leaderboard" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"rank": 1, "name": "Alice", "total_stars": 10},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/gamification/stars/leaderboard?limit=20", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestGamificationMissionsRequireAuth(t *testing.T) {
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"})
	h := New(pr, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/gamification/missions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestGamificationClaimRequiresAuth(t *testing.T) {
	auth.ConfigureGoTrueAuth("secret")
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"})
	h := New(pr, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/gamification/missions/daily_play/claim", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestGamificationListMissionsWithGoTrueToken(t *testing.T) {
	const secret = "gotrue-test-secret"
	auth.ConfigureGoTrueAuth(secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_user_missions_v2" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"code": "daily_play", "completed": false},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/gamification/missions", nil)
	req.Header.Set("Authorization", "Bearer "+testsupport.GoTrueJWT(t, secret, "u1", "player@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestGamificationClaimWithGoTrueToken(t *testing.T) {
	const secret = "gotrue-test-secret"
	auth.ConfigureGoTrueAuth(secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/claim_mission_v2" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(true)
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/gamification/missions/daily_play/claim", nil)
	req.Header.Set("Authorization", "Bearer "+testsupport.GoTrueJWT(t, secret, "u1", "player@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}
