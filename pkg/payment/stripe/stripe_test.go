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

	stripesdk "github.com/stripe/stripe-go/v82"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

func nowUnix() int64 { return time.Now().Unix() }

func TestSubStatusMapping(t *testing.T) {
	cases := map[stripesdk.SubscriptionStatus]payment.Status{
		stripesdk.SubscriptionStatusActive:     payment.StatusActive,
		stripesdk.SubscriptionStatusTrialing:   payment.StatusActive,
		stripesdk.SubscriptionStatusCanceled:   payment.StatusCanceled,
		stripesdk.SubscriptionStatusPastDue:    payment.StatusPastDue,
		stripesdk.SubscriptionStatusUnpaid:     payment.StatusPastDue,
		stripesdk.SubscriptionStatusIncomplete: payment.StatusPending,
	}
	for in, want := range cases {
		if got := subStatus(in); got != want {
			t.Errorf("subStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestStripeWebhookSubscriptionEvents verifies subscription lifecycle webhooks map to the
// normalized EventSub* kinds with the provider subscription id (and ref id on activation).
func TestStripeWebhookSubscriptionEvents(t *testing.T) {
	const whsec = "whsec_test"
	c := New(Config{WebhookSecret: whsec}).(*Client) // no secret key → activation skips the API retrieve
	mux := http.NewServeMux()
	var captured []payment.Event
	c.RegisterRoutes(router.New(mux, payment.WebhookPathPrefix), func(_ context.Context, e payment.Event) error {
		captured = append(captured, e)
		return nil
	})

	post := func(t *testing.T, raw []byte) {
		t.Helper()
		body, header := buildSignedPayload(t, raw, whsec)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/stripe", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", header)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
		}
	}

	t.Run("checkout.session.completed → activated", func(t *testing.T) {
		captured = nil
		post(t, []byte(fmt.Sprintf(`{"id":"evt_1","object":"event","api_version":"2025-08-27.basil","type":"checkout.session.completed","created":%d,
			"data":{"object":{"id":"cs_1","object":"checkout.session","mode":"subscription","subscription":"sub_1","client_reference_id":"42"}}}`, nowUnix())))
		if len(captured) != 1 || captured[0].Kind != payment.EventSubActivated {
			t.Fatalf("got %+v", captured)
		}
		if captured[0].ProviderSubID != "sub_1" || captured[0].RefID != "42" {
			t.Fatalf("sub/ref mismatch: %+v", captured[0])
		}
	})

	t.Run("payment-mode session ignored", func(t *testing.T) {
		captured = nil
		post(t, []byte(fmt.Sprintf(`{"id":"evt_2","object":"event","api_version":"2025-08-27.basil","type":"checkout.session.completed","created":%d,
			"data":{"object":{"id":"cs_2","object":"checkout.session","mode":"payment","client_reference_id":"7"}}}`, nowUnix())))
		if len(captured) != 0 {
			t.Fatalf("payment-mode session must not emit, got %+v", captured)
		}
	})

	t.Run("invoice.payment_succeeded cycle → renewed", func(t *testing.T) {
		captured = nil
		post(t, []byte(fmt.Sprintf(`{"id":"evt_3","object":"event","api_version":"2025-08-27.basil","type":"invoice.payment_succeeded","created":%d,
			"data":{"object":{"id":"in_1","object":"invoice","billing_reason":"subscription_cycle",
			"parent":{"type":"subscription_details","subscription_details":{"subscription":"sub_1"}},
			"lines":{"object":"list","data":[{"object":"line_item","period":{"start":1,"end":999}}]}}}}`, nowUnix())))
		if len(captured) != 1 || captured[0].Kind != payment.EventSubRenewed {
			t.Fatalf("got %+v", captured)
		}
		if captured[0].ProviderSubID != "sub_1" || captured[0].PeriodEnd != 999 {
			t.Fatalf("renew mismatch: %+v", captured[0])
		}
	})

	t.Run("invoice.payment_succeeded create ignored", func(t *testing.T) {
		captured = nil
		post(t, []byte(fmt.Sprintf(`{"id":"evt_4","object":"event","api_version":"2025-08-27.basil","type":"invoice.payment_succeeded","created":%d,
			"data":{"object":{"id":"in_2","object":"invoice","billing_reason":"subscription_create",
			"parent":{"type":"subscription_details","subscription_details":{"subscription":"sub_1"}},
			"lines":{"object":"list","data":[{"object":"line_item","period":{"start":1,"end":50}}]}}}}`, nowUnix())))
		if len(captured) != 0 {
			t.Fatalf("subscription_create must be ignored (handled by checkout.session.completed), got %+v", captured)
		}
	})

	t.Run("customer.subscription.deleted → canceled", func(t *testing.T) {
		captured = nil
		post(t, []byte(fmt.Sprintf(`{"id":"evt_5","object":"event","api_version":"2025-08-27.basil","type":"customer.subscription.deleted","created":%d,
			"data":{"object":{"id":"sub_1","object":"subscription","status":"canceled"}}}`, nowUnix())))
		if len(captured) != 1 || captured[0].Kind != payment.EventSubCanceled || captured[0].Status != payment.StatusCanceled {
			t.Fatalf("got %+v", captured)
		}
	})
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
//  1. Valid signed payment_intent.succeeded → Event{ProviderID,RefID,Status}.
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
	c.RegisterRoutes(router.New(mux, payment.WebhookPathPrefix), deliver)

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
		if e.RefID != "55" {
			t.Errorf("RefID: want %q, got %q", "55", e.RefID)
		}
		if e.Status != payment.StatusSuccess {
			t.Errorf("Status: want %q, got %q", payment.StatusSuccess, e.Status)
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
		if e.RefID != "88" {
			t.Errorf("RefID: want %q, got %q", "88", e.RefID)
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
