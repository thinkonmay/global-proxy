package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func hit(t *testing.T, mux *http.ServeMux, method, target string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec.Code
}

func TestGroupPrefixesAndAliases(t *testing.T) {
	mux := http.NewServeMux()
	v1 := V1(mux)
	v1.GET("/billing/wallet", func(w http.ResponseWriter, r *http.Request) {})
	v1.POST("/billing/payments", func(w http.ResponseWriter, r *http.Request) {})

	cases := []struct {
		method, target string
		want           int
	}{
		{http.MethodGet, "/v1/billing/wallet", http.StatusOK},                 // prefixed
		{http.MethodGet, "/v1/billing/wallet/", http.StatusOK},                // trailing-slash alias
		{http.MethodPost, "/v1/billing/payments", http.StatusOK},              // method routed
		{http.MethodGet, "/v1/billing/payments", http.StatusMethodNotAllowed}, // wrong method
		{http.MethodGet, "/billing/wallet", http.StatusNotFound},              // unprefixed must miss
	}
	for _, c := range cases {
		if got := hit(t, mux, c.method, c.target); got != c.want {
			t.Errorf("%s %s: got %d want %d", c.method, c.target, got, c.want)
		}
	}
}

func TestWildcardPathGetsNoTrailingAlias(t *testing.T) {
	// A "{name...}" wildcard already matches deep paths; registering a
	// "{name...}/" alias would be an invalid pattern and panic at registration.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("wildcard route panicked on registration: %v", r)
		}
	}()
	mux := http.NewServeMux()
	V1(mux).GET("/files/{path...}", func(w http.ResponseWriter, r *http.Request) {})

	if got := hit(t, mux, http.MethodGet, "/v1/files/a/b/c"); got != http.StatusOK {
		t.Errorf("wildcard match: got %d want 200", got)
	}
}

func TestNewTrimsPrefixSlashAndCustomPrefix(t *testing.T) {
	mux := http.NewServeMux()
	New(mux, "/api/v1/payment/webhook/").POST("/stripe", func(w http.ResponseWriter, r *http.Request) {})
	if got := hit(t, mux, http.MethodPost, "/api/v1/payment/webhook/stripe"); got != http.StatusOK {
		t.Errorf("custom prefix: got %d want 200", got)
	}
}
