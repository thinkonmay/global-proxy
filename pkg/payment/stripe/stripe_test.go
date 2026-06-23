package stripe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

// TestMapPaymentIntentStatus verifies the mapPI status mapping function.
// The off-session PaymentIntents.Create call requires live Stripe credentials
// and is NOT covered here; only the pure mapping logic is unit-tested.
func TestMapPaymentIntentStatus(t *testing.T) {
	cases := []struct {
		input string
		want  payment.Status
	}{
		{"succeeded", payment.StatusSuccess},
		{"canceled", payment.StatusCanceled},
		{"requires_action", payment.StatusPending},
		{"processing", payment.StatusPending},
		{"requires_confirmation", payment.StatusPending},
		{"requires_payment_method", payment.StatusPending},
		{"unknown_status", payment.StatusPending},
		{"", payment.StatusPending},
	}
	for _, tc := range cases {
		got := mapPI(tc.input)
		if got != tc.want {
			t.Errorf("mapPI(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// buildSignedPayload computes a Stripe-Signature header for body using secret.
// Format: t=<unix>,v1=<hex(hmac_sha256(secret, "<unix>.<body>"))>
func buildSignedPayload(t *testing.T, body []byte, secret string) (payload []byte, header string) {
	t.Helper()
	ts := time.Now().Unix()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d", ts)))
	mac.Write([]byte("."))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	return body, fmt.Sprintf("t=%d,v1=%s", ts, sig)
}

// minimalPISucceededEvent builds a payment_intent.succeeded webhook JSON.
// api_version matches stripe-go v82.5.1 (2025-08-27.basil).
func minimalPISucceededEvent(txnID, pmID, cusID string) []byte {
	return []byte(fmt.Sprintf(`{
		"id": "evt_test_001",
		"object": "event",
		"api_version": "2025-08-27.basil",
		"type": "payment_intent.succeeded",
		"created": %d,
		"data": {
			"object": {
				"id": "pi_test_001",
				"object": "payment_intent",
				"metadata": {"txn_id": %q},
				"payment_method": %q,
				"customer": %q,
				"status": "succeeded"
			}
		}
	}`, time.Now().Unix(), txnID, pmID, cusID))
}

func minimalPIFailedEvent(txnID string) []byte {
	return []byte(fmt.Sprintf(`{
		"id": "evt_test_002",
		"object": "event",
		"api_version": "2025-08-27.basil",
		"type": "payment_intent.payment_failed",
		"created": %d,
		"data": {
			"object": {
				"id": "pi_test_002",
				"object": "payment_intent",
				"metadata": {"txn_id": %q},
				"status": "requires_payment_method"
			}
		}
	}`, time.Now().Unix(), txnID))
}

// TestStripeWebhookEmitsEvent verifies signature-verified webhook ingestion:
//  1. Valid signed payment_intent.succeeded → Event{ID,Status,Token,CustomerRef}.
//  2. Tampered/wrong-secret signature → HTTP 400, no deliver call.
//  3. Garbage signature header → HTTP 400.
//  4. payment_intent.payment_failed → Event with StatusFailed.
//  5. Unknown event type → HTTP 200, no deliver call.
func TestStripeWebhookEmitsEvent(t *testing.T) {
	const whsec = "whsec_test"

	c := New(Config{WebhookSecret: whsec}).(*Client)
	mux := http.NewServeMux()

	var captured []payment.Event
	deliver := func(_ context.Context, e payment.Event) error {
		captured = append(captured, e)
		return nil
	}
	c.RegisterRoutes(mux, deliver)

	t.Run("valid_signature_emits_event", func(t *testing.T) {
		captured = nil
		body, header := buildSignedPayload(t, minimalPISucceededEvent("55", "pm_x", "cus_x"), whsec)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/stripe", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", header)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if len(captured) != 1 {
			t.Fatalf("expected 1 event delivered, got %d", len(captured))
		}
		e := captured[0]
		if e.ID != "55" {
			t.Errorf("ID: want %q, got %q", "55", e.ID)
		}
		if e.Status != payment.StatusSuccess {
			t.Errorf("Status: want %q, got %q", payment.StatusSuccess, e.Status)
		}
		if e.Token != "pm_x" {
			t.Errorf("Token: want %q, got %q", "pm_x", e.Token)
		}
		if e.CustomerRef != "cus_x" {
			t.Errorf("CustomerRef: want %q, got %q", "cus_x", e.CustomerRef)
		}
		if e.Kind != payment.EventCharge {
			t.Errorf("Kind: want %q, got %q", payment.EventCharge, e.Kind)
		}
	})

	t.Run("tampered_signature_returns_400", func(t *testing.T) {
		captured = nil
		body := minimalPISucceededEvent("99", "pm_y", "cus_y")
		// Signed with wrong secret
		_, header := buildSignedPayload(t, body, "wrong_secret")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/stripe", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", header)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
		if len(captured) != 0 {
			t.Errorf("deliver must not be called on bad signature; captured %d events", len(captured))
		}
	})

	t.Run("garbage_signature_returns_400", func(t *testing.T) {
		captured = nil
		body := minimalPISucceededEvent("77", "pm_z", "cus_z")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/stripe", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", "t=garbage,v1=notahexstring")
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
		if len(captured) != 0 {
			t.Errorf("deliver must not be called on garbage signature; captured %d events", len(captured))
		}
	})

	t.Run("payment_failed_emits_failed_status", func(t *testing.T) {
		captured = nil
		body, header := buildSignedPayload(t, minimalPIFailedEvent("88"), whsec)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/stripe", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", header)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if len(captured) != 1 {
			t.Fatalf("expected 1 event for payment_failed, got %d", len(captured))
		}
		e := captured[0]
		if e.ID != "88" {
			t.Errorf("ID: want %q, got %q", "88", e.ID)
		}
		if e.Status != payment.StatusFailed {
			t.Errorf("Status: want %q, got %q", payment.StatusFailed, e.Status)
		}
		if e.Kind != payment.EventCharge {
			t.Errorf("Kind: want %q, got %q", payment.EventCharge, e.Kind)
		}
	})

	t.Run("unknown_event_type_returns_200_no_deliver", func(t *testing.T) {
		captured = nil
		body := []byte(fmt.Sprintf(`{
			"id": "evt_test_003",
			"object": "event",
			"api_version": "2025-08-27.basil",
			"type": "customer.created",
			"created": %d,
			"data": {"object": {"id": "cus_zzz", "object": "customer"}}
		}`, time.Now().Unix()))
		_, header := buildSignedPayload(t, body, whsec)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/stripe", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", header)

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if len(captured) != 0 {
			t.Errorf("expected 0 events for unknown type, got %d", len(captured))
		}
	})

	t.Run("empty_txn_id_returns_400_no_deliver", func(t *testing.T) {
		captured = nil
		// Build a payment_intent.succeeded event with empty txn_id
		body, header := buildSignedPayload(t, minimalPISucceededEvent("", "pm_empty", "cus_empty"), whsec)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/stripe", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", header)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty txn_id, got %d: %s", rr.Code, rr.Body.String())
		}
		if len(captured) != 0 {
			t.Errorf("deliver must not be called when txn_id is empty; captured %d events", len(captured))
		}
	})

	t.Run("empty_txn_id_payment_failed_returns_400_no_deliver", func(t *testing.T) {
		captured = nil
		// Build a payment_intent.payment_failed event with empty txn_id
		body, header := buildSignedPayload(t, minimalPIFailedEvent(""), whsec)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/stripe", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", header)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty txn_id in payment_failed, got %d: %s", rr.Code, rr.Body.String())
		}
		if len(captured) != 0 {
			t.Errorf("deliver must not be called when txn_id is empty; captured %d events", len(captured))
		}
	})
}
