package payssion

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

func sign(cfg Config, pmID, amount, currency, trackID, subTrackID, state string) string {
	raw := cfg.APIKey + "|" + pmID + "|" + amount + "|" + currency + "|" +
		trackID + "|" + subTrackID + "|" + state + "|" + cfg.SecretKey
	return fmt.Sprintf("%x", md5.Sum([]byte(raw)))
}

func postForm(mux *http.ServeMux, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/payssion", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPayssionWebhookDeliversTerminal(t *testing.T) {
	cfg := Config{APIKey: "ak", PMID: "pm", SecretKey: "sk", Link: "http://x"}
	c := &Client{cfg: cfg}
	mux := http.NewServeMux()
	var got payment.Event
	delivered := false
	c.RegisterRoutes(mux, func(_ context.Context, e payment.Event) error {
		got, delivered = e, true
		return nil
	})

	form := url.Values{}
	form.Set("pm_id", "pm")
	form.Set("amount", "25000")
	form.Set("currency", "VND")
	form.Set("track_id", "TRK")
	form.Set("sub_track_id", "SUB")
	form.Set("order_id", "42")
	form.Set("state", "completed")
	form.Set("notify_sig", sign(cfg, "pm", "25000", "VND", "TRK", "SUB", "completed"))

	rec := postForm(mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body %s", rec.Code, rec.Body.String())
	}
	if !delivered {
		t.Fatal("event not delivered")
	}
	// RefID = order_id (our txn id); ProviderID = track_id (Payssion's id).
	if got.Kind != payment.EventCharge || got.RefID != "42" || got.ProviderID != "TRK" || got.Status != payment.StatusSuccess {
		t.Fatalf("event = %+v", got)
	}
}

func TestPayssionGetChargeTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/payment/details" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result_code": 200,
			"transaction": map[string]any{"state": "completed", "transaction_id": "TRK"},
		})
	}))
	defer srv.Close()

	c := New(Config{APIKey: "ak", SecretKey: "sk", Link: srv.URL})
	ch, err := c.GetCharge(context.Background(), "42")
	if err != nil {
		t.Fatal(err)
	}
	if ch.ID != "42" || ch.Status != payment.StatusSuccess {
		t.Fatalf("charge = %+v", ch)
	}
}

func TestPayssionGetChargePendingNotSettled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result_code": 200, "state": "pending"})
	}))
	defer srv.Close()

	c := New(Config{APIKey: "ak", SecretKey: "sk", Link: srv.URL})
	ch, err := c.GetCharge(context.Background(), "42")
	if err != nil {
		t.Fatal(err)
	}
	// Non-terminal → pending so the poller does not settle.
	if ch.Status != payment.StatusPending {
		t.Fatalf("status = %v, want pending", ch.Status)
	}
}

func TestPayssionWebhookRejectsBadSig(t *testing.T) {
	c := &Client{cfg: Config{APIKey: "ak", SecretKey: "sk"}}
	mux := http.NewServeMux()
	c.RegisterRoutes(mux, func(context.Context, payment.Event) error { return nil })

	form := url.Values{}
	form.Set("order_id", "42")
	form.Set("state", "completed")
	form.Set("notify_sig", "deadbeef")

	if rec := postForm(mux, form); rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

func TestPayssionWebhookAcksNonTerminal(t *testing.T) {
	cfg := Config{APIKey: "ak", SecretKey: "sk"}
	c := &Client{cfg: cfg}
	mux := http.NewServeMux()
	delivered := false
	c.RegisterRoutes(mux, func(context.Context, payment.Event) error { delivered = true; return nil })

	form := url.Values{}
	form.Set("amount", "1")
	form.Set("currency", "VND")
	form.Set("track_id", "TRK")
	form.Set("sub_track_id", "SUB")
	form.Set("order_id", "42")
	form.Set("state", "pending")
	form.Set("notify_sig", sign(cfg, "", "1", "VND", "TRK", "SUB", "pending"))

	rec := postForm(mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if delivered {
		t.Fatal("non-terminal state must not deliver an event")
	}
}
