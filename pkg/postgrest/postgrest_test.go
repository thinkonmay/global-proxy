package postgrest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func newTestClient(url string) *Client {
	return New(Config{URL: url, AnonKey: "anon-key", ServiceKey: "service-key"})
}

func TestUpdateSendsPatchWithFilter(t *testing.T) {
	var gotMethod, gotFilter, gotContentType string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotFilter = r.URL.Query().Get("id")
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	q := url.Values{}
	q.Set("id", "eq.7")
	if err := newTestClient(srv.URL).Update(context.Background(), "job", q, map[string]any{"success": true}, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %s, want PATCH", gotMethod)
	}
	if gotFilter != "eq.7" {
		t.Errorf("id filter = %q, want eq.7", gotFilter)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotBody["success"] != true {
		t.Errorf("body success = %v, want true", gotBody["success"])
	}
}

func TestInsertDecodesRepresentation(t *testing.T) {
	var gotPrefer, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/job" {
			t.Errorf("got %s %s, want POST /job", r.Method, r.URL.Path)
		}
		gotPrefer = r.Header.Get("Prefer")
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`[{"id":7}]`))
	}))
	defer srv.Close()

	var rows []struct {
		ID int64 `json:"id"`
	}
	if err := newTestClient(srv.URL).Insert(context.Background(), "job", map[string]any{"command": "x"}, &rows); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if gotPrefer != "return=representation" {
		t.Errorf("Prefer = %q, want return=representation (dest non-nil)", gotPrefer)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if len(rows) != 1 || rows[0].ID != 7 {
		t.Errorf("rows = %+v, want [{7}]", rows)
	}
}

func TestSelectBuildsQueryAndDecodes(t *testing.T) {
	var gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`[{"id":5}]`))
	}))
	defer srv.Close()

	q := url.Values{}
	q.Set("id", "eq.5")
	q.Set("limit", "1")
	var rows []struct {
		ID int64 `json:"id"`
	}
	if err := newTestClient(srv.URL).Select(context.Background(), "job", q, &rows); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if gotRawQuery != "id=eq.5&limit=1" {
		t.Errorf("raw query = %q, want id=eq.5&limit=1", gotRawQuery)
	}
	if len(rows) != 1 || rows[0].ID != 5 {
		t.Errorf("rows = %+v, want [{5}]", rows)
	}
}

func TestInjectsAuthHeaders(t *testing.T) {
	var apikey, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apikey = r.Header.Get("apikey")
		auth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	// reads use the anon key
	if err := newTestClient(srv.URL).Select(context.Background(), "job", nil, nil); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if apikey != "anon-key" {
		t.Errorf("apikey = %q, want anon-key", apikey)
	}
	if auth != "Bearer anon-key" {
		t.Errorf("Authorization = %q, want Bearer anon-key", auth)
	}
}

func TestInsertUsesServiceKey(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	if err := newTestClient(srv.URL).Insert(context.Background(), "job", map[string]any{}, nil); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if auth != "Bearer service-key" {
		t.Errorf("Authorization = %q, want Bearer service-key", auth)
	}
}

func TestNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"bad"}`))
	}))
	defer srv.Close()

	if err := newTestClient(srv.URL).Select(context.Background(), "job", nil, nil); err == nil {
		t.Fatal("expected error on 400, got nil")
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.timeout = 10 * time.Millisecond
	if err := c.Select(context.Background(), "job", nil, nil); err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
