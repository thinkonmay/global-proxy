package postgrest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestDeleteSendsDelete(t *testing.T) {
	var method, filter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		filter = r.URL.Query().Get("id")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv.URL).Delete(context.Background(), "msg", url.Values{"id": {"eq.7"}}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if method != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", method)
	}
	if filter != "eq.7" {
		t.Errorf("filter = %q, want eq.7", filter)
	}
}

func TestConflictIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"23505","message":"duplicate key"}`))
	}))
	defer srv.Close()

	err := newTestClient(srv.URL).Insert(context.Background(), "msg", map[string]any{"id": 7}, nil)
	if err == nil {
		t.Fatal("expected error on 409")
	}
	if !IsConflict(err) {
		t.Errorf("IsConflict = false, want true for 409 (%v)", err)
	}
}

func TestNon409IsNotConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	err := newTestClient(srv.URL).Insert(context.Background(), "msg", map[string]any{"id": 7}, nil)
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if IsConflict(err) {
		t.Errorf("IsConflict = true, want false for 400")
	}
}
