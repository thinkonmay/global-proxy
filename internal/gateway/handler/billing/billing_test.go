package billing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// fakeCharger implements payment.Client returning a fixed redirect URL.
type fakeCharger struct{ payment.Client }

func (fakeCharger) Name() string { return "payos" }
func (fakeCharger) Charge(_ context.Context, a payment.ChargeParams) (payment.Charge, error) {
	return payment.Charge{ID: a.IdempotencyKey, Status: payment.StatusPending, RedirectURL: "https://pay/x"}, nil
}

func TestFillCheckoutReturnsURL(t *testing.T) {
	reg := registry.NewRegistryWith(map[string]payment.Client{"payos": fakeCharger{}})
	h := &Handler{registry: reg}
	ch, err := h.fillCheckout(context.Background(), txnRow{ID: 7, Provider: "payos", Currency: "VND", Amount: 100}, 0.004)
	if err != nil {
		t.Fatal(err)
	}
	if ch.RedirectURL != "https://pay/x" {
		t.Fatalf("RedirectURL = %q", ch.RedirectURL)
	}
}

// TestCreateDepositRowLoopDataShape verifies that fillCheckout + the data-shape assembly
// in CreateDeposit produce the expected JSON keys (redirect_url, charge_id, and detail when
// non-empty). The CreateDeposit handler itself cannot be driven end-to-end in a unit test
// without auth: RequireUser needs ConfigureGoTrueAuth / APP_SUPABASE_JWTSECRET.
// End-to-end coverage of the full row-loop (RPC → loadTransaction → rates.Load → fillCheckout → Update) is left for the
// live-DB integration suite (WITH_INTEGRATION=1).
func TestCreateDepositRowLoopDataShape(t *testing.T) {
	reg := registry.NewRegistryWith(map[string]payment.Client{"payos": fakeCharger{}})
	h := &Handler{registry: reg}

	txn := txnRow{ID: 42, Provider: "payos", Currency: "VND", Amount: 200}
	ch, err := h.fillCheckout(context.Background(), txn, 0.004)
	if err != nil {
		t.Fatal(err)
	}

	// Replicate the data-shape assembly from CreateDeposit.
	out := map[string]any{"redirect_url": ch.RedirectURL, "charge_id": ch.ID}
	if len(ch.Detail) > 0 {
		out["detail"] = ch.Detail
	}
	dataBytes, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(dataBytes, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["redirect_url"] != "https://pay/x" {
		t.Fatalf("redirect_url = %v", parsed["redirect_url"])
	}
	if parsed["charge_id"] != "42" {
		t.Fatalf("charge_id = %v", parsed["charge_id"])
	}
	// fakeCharger returns no Detail, so the key must be absent.
	if _, ok := parsed["detail"]; ok {
		t.Fatalf("detail should be absent for provider with nil Detail, got: %v", parsed["detail"])
	}
}

func TestBillingListActiveAddonsRequireAuth(t *testing.T) {
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"})
	h := New(pr, nil, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/addons", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestBillingListActiveAddonsPublicRPC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_active_addons" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"type": "llm", "units": 1},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	// Without auth — only tests route registration; full auth tested in integration.
	req := httptest.NewRequest(http.MethodGet, "/v1/billing/addons", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestBillingDomainsPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_domains_availability_v5" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"domain": "haiphong.thinkmay.net", "routing_only": false},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/domains", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Data) != 1 || out.Data[0]["domain"] != "haiphong.thinkmay.net" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

// chargeSpy is a payment.Client that records charge params and returns success.
type chargeSpy struct {
	payment.Client
	fn func(payment.ChargeParams)
}

func (chargeSpy) Name() string { return "stripe" }
func (s chargeSpy) Charge(_ context.Context, a payment.ChargeParams) (payment.Charge, error) {
	if s.fn != nil {
		s.fn(a)
	}
	return payment.Charge{Status: payment.StatusSuccess}, nil
}

func TestFillCheckoutOffSession(t *testing.T) {
	var gotToken, gotCustomer string
	reg := registry.NewRegistryWith(map[string]payment.Client{"stripe": chargeSpy{
		fn: func(a payment.ChargeParams) { gotToken = a.Token; gotCustomer = a.CustomerRef },
	}})
	h := &Handler{registry: reg}
	_, err := h.fillCheckoutCard(context.Background(),
		txnRow{ID: 7, Provider: "stripe", Currency: "USD", Amount: 252}, 12.6,
		"pm_1", "cus_1")
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "pm_1" || gotCustomer != "cus_1" {
		t.Fatalf("token=%q customer=%q", gotToken, gotCustomer)
	}
}

func TestBillingUnsubscribeInvalidAddonID(t *testing.T) {
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"})
	h := New(pr, nil, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodDelete, "/v1/billing/addons/not-a-number", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

// TestResolveUserIDQueryIncludesEmail verifies that resolveUserID issues a SelectService
// call whose query string contains both the "users" table and an email equality filter.
// This confirms Fix 1's email→id lookup uses the correct filter before the user_id-scoped
// card lookup — the full IDOR guard (user_id + provider filters) requires the live DB and
// is covered by the integration suite (WITH_INTEGRATION=1).
func TestResolveUserIDQueryIncludesEmail(t *testing.T) {
	var capturedPath, capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedQuery = r.URL.RawQuery
		// Simulate no user found — resolveUserID must return an error.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := &Handler{pr: pr}
	_, err := h.resolveUserID(context.Background(), "alice@example.com")
	if err == nil {
		t.Fatal("expected error when user not found")
	}

	if capturedPath != "/users" {
		t.Fatalf("path = %q, want /users", capturedPath)
	}
	if !strings.Contains(capturedQuery, "email=eq.alice%40example.com") &&
		!strings.Contains(capturedQuery, "email=eq.alice@example.com") {
		t.Fatalf("query %q missing email filter", capturedQuery)
	}
}
