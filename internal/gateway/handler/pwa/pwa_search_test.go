package pwa

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func testJWT(t *testing.T) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "u1",
		"email": "thinkmay@dev.net",
		"role":  "authenticated",
		"aud":   "authenticated",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSearchMissingDescription(t *testing.T) {
	h := New(config.Config{LLM: config.LLM{BaseURL: "http://127.0.0.1:1", APIKey: "k", Model: "test"}}, nil, nil, persona.New(nil, nil), nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/search/ai", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSearchNotConfigured(t *testing.T) {
	auth.ConfigureGoTrueAuth("test-secret")
	t.Cleanup(func() { auth.ConfigureGoTrueAuth("") })

	h := New(config.Config{}, postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"}), nil, persona.New(nil, nil), nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	body := bytes.NewBufferString(`{"description":"cozy farming sim"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/search/ai", body)
	req.Header.Set("Authorization", "Bearer "+testJWT(t))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPwaSearchToolsIncludesGoogleWhenSerpAPIConfigured(t *testing.T) {
	h := New(config.Config{
		LLM:      config.LLM{BaseURL: "http://127.0.0.1:1", APIKey: "k", Model: "test"},
		SerpAPI:  config.SerpAPI{APIKey: "serp-key"},
	}, nil, nil, persona.New(nil, nil), nil, nil)
	tools := h.pwaSearchTools()
	if len(tools) != 2 {
		t.Fatalf("tools=%d", len(tools))
	}
	fn, _ := tools[1]["function"].(map[string]any)
	if fn["name"] != "google_search" {
		t.Fatalf("name=%v", fn["name"])
	}
}

func TestPwaSearchToolsOmitsGoogleWithoutSerpAPIKey(t *testing.T) {
	h := New(config.Config{
		LLM: config.LLM{BaseURL: "http://127.0.0.1:1", APIKey: "k", Model: "test"},
	}, nil, nil, persona.New(nil, nil), nil, nil)
	if len(h.pwaSearchTools()) != 1 {
		t.Fatal("expected only search_steam")
	}
}

func TestSearchV1RouteRegistered(t *testing.T) {
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"finish_reason": "stop",
				"message": map[string]any{
					"content": `{"suggestion":"Try these","games":[]}`,
				},
			}},
		})
	}))
	t.Cleanup(llm.Close)

	auth.ConfigureGoTrueAuth("test-secret")
	t.Cleanup(func() { auth.ConfigureGoTrueAuth("") })

	pr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/search_stores":
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(pr.Close)

	h := New(
		config.Config{LLM: config.LLM{BaseURL: llm.URL + "/v1", APIKey: "k", Model: "test"}},
		postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}),
		nil,
		persona.New(postgrest.New(postgrest.Config{URL: pr.URL, ServiceKey: "svc"}), nil), nil,
		nil,
	)
	mux := http.NewServeMux()
	h.Register(mux)

	body := bytes.NewBufferString(`{"description":"relaxing puzzle games"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/search/ai", body)
	req.Header.Set("Authorization", "Bearer "+testJWT(t))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["suggestion"] != "Try these" {
		t.Fatalf("suggestion=%v", out["suggestion"])
	}
}
