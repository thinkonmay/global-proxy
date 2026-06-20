package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	testAnonKey    = "anon-key"
	testServiceKey = "service-role-key"
)

func testKeys() *Keys {
	return NewKeys(testAnonKey, testAnonKey, testServiceKey, testServiceKey)
}

func TestRequireKeyRejectsInvalidKey(t *testing.T) {
	h := RequireKey(testKeys(), PolicyAnonAndAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/plans", nil)
	req.Header.Set("apikey", "not-a-valid-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireKeyRejectsMissingKey(t *testing.T) {
	h := RequireKey(testKeys(), PolicyAnonAndAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rest/v1/stores", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireKeyAcceptsAnonKey(t *testing.T) {
	var gotAuth string
	h := RequireKey(testKeys(), PolicyAnonAndAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/stores", nil)
	req.Header.Set("apikey", testAnonKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotAuth != "Bearer "+testAnonKey {
		t.Fatalf("expected anon bearer, got code=%d auth=%q", rec.Code, gotAuth)
	}
}

func TestRequireKeyAdminOnlyRejectsAnon(t *testing.T) {
	h := RequireKey(testKeys(), PolicyAdminOnly)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/pg/tables", nil)
	req.Header.Set("apikey", testAnonKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequireKeyAdminOnlyAcceptsServiceKey(t *testing.T) {
	called := false
	h := RequireKey(testKeys(), PolicyAdminOnly)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/pg/tables", nil)
	req.Header.Set("Authorization", "Bearer "+testServiceKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected service key pass, got called=%v code=%d", called, rec.Code)
	}
}

func TestStorageAuthClearsEmptyAuthorization(t *testing.T) {
	var authHeader string
	h := StorageAuth(testKeys())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/storage/v1/object/public/x", nil)
	req.Header.Set("Authorization", "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if authHeader != "" {
		t.Fatalf("expected cleared Authorization, got %q", authHeader)
	}
}

func TestStorageAuthTransformsKnownKey(t *testing.T) {
	var authHeader string
	h := StorageAuth(testKeys())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/storage/v1/object/sign/x", nil)
	req.Header.Set("apikey", testServiceKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if authHeader != "Bearer "+testServiceKey {
		t.Fatalf("expected transformed auth, got %q", authHeader)
	}
}

func TestBasicAuthRejectsMissingCredentials(t *testing.T) {
	h := BasicAuth("studio", "secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBasicAuthAcceptsValidCredentials(t *testing.T) {
	called := false
	h := BasicAuth("studio", "secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("studio", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected pass, got called=%v code=%d", called, rec.Code)
	}
}

func TestExtractKeyFromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/storage/v1/object/sign/x?apikey=abc", nil)
	key, ok := ExtractKey(req)
	if !ok || key != "abc" {
		t.Fatalf("expected query apikey, got ok=%v key=%q", ok, key)
	}
}
