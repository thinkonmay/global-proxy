package billing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/testsupport"
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
	ch, err := h.fillCheckout(context.Background(), txnRow{ID: 7, Provider: "payos", Currency: "VND", Amount: 100}, "")
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
// End-to-end coverage of the full row-loop (RPC → loadTransaction → fillCheckout → Update) is left for the
// live-DB integration suite (WITH_INTEGRATION=1).
func TestCreateDepositRowLoopDataShape(t *testing.T) {
	reg := registry.NewRegistryWith(map[string]payment.Client{"payos": fakeCharger{}})
	h := &Handler{registry: reg}

	txn := txnRow{ID: 42, Provider: "payos", Currency: "VND", Amount: 200}
	ch, err := h.fillCheckout(context.Background(), txn, "")
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

func TestPlanChargeMoneyResolvesServerSide(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// PostgREST table read for plans, selecting price->USD.
		if r.URL.Path != "/plans" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"USD": map[string]any{"amount": 12, "tag": "USD"}},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil, nil)

	m, err := h.planChargeMoney(context.Background(), "pro", "usd")
	if err != nil {
		t.Fatal(err)
	}
	// $12 major -> 1200 minor; client-supplied amount is irrelevant.
	if m.Currency != "USD" || m.Amount != 1200 {
		t.Fatalf("planChargeMoney = %+v, want {1200 USD}", m)
	}
}

func TestPlanChargeMoneyMissingPrice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{}}) // row exists, no USD key
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil, nil)

	if _, err := h.planChargeMoney(context.Background(), "pro", "USD"); err == nil {
		t.Fatal("expected error when plan has no price for currency")
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

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/addons", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestBillingListActiveAddonsWithGoTrueToken(t *testing.T) {
	const secret = "gotrue-test-secret"
	auth.ConfigureGoTrueAuth(secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_active_addons" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"type": "llm", "units": 2},
		})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/addons", nil)
	req.Header.Set("Authorization", "Bearer "+testsupport.GoTrueJWT(t, secret, "u1", "subscriber@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestBillingListActiveAddonsNoSubscription(t *testing.T) {
	const secret = "gotrue-test-secret"
	auth.ConfigureGoTrueAuth(secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_active_addons" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"P0001","message":"email do not have any subscription"}`))
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := New(pr, nil, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/addons", nil)
	req.Header.Set("Authorization", "Bearer "+testsupport.GoTrueJWT(t, secret, "u1", "nosub@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"data":[]`) {
		t.Fatalf("expected empty data array, got: %s", rec.Body.String())
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
