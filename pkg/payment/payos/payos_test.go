package payos

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

func TestMapStatusCanonical(t *testing.T) {
	cases := map[string]payment.Status{
		"PAID":      payment.StatusSuccess,
		"CANCELLED": payment.StatusCanceled, // const value must equal "cancelled"
		"EXPIRED":   payment.StatusCanceled,
		"PENDING":   payment.StatusPending,
	}
	for in, want := range cases {
		if got := mapStatus(in); got != want {
			t.Fatalf("mapStatus(%q) = %q, want %q", in, got, want)
		}
	}
	if string(payment.StatusCanceled) != "cancelled" {
		t.Fatalf("StatusCanceled = %q, want cancelled", payment.StatusCanceled)
	}
}

const testChecksumKey = "test-checksum-key"

// signData mirrors PayOS's scheme: keys sorted, joined key=value&..., HMAC-SHA256.
func signData(t *testing.T, data map[string]any, key string) string {
	t.Helper()
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		var v string
		switch val := data[k].(type) {
		case nil:
			v = ""
		case string:
			v = val
		case int:
			v = strconv.Itoa(val)
		default:
			t.Fatalf("unsupported test value type for key %q", k)
		}
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(strings.Join(pairs, "&")))
	return hex.EncodeToString(mac.Sum(nil))
}

func newPayOSWebhook(t *testing.T, orderCode int, code string) []byte {
	t.Helper()
	data := map[string]any{
		"orderCode":     orderCode,
		"amount":        3000,
		"description":   "thinkmay",
		"accountNumber": "12345678",
		"reference":     "TF230204212323",
		"currency":      "VND",
		"paymentLinkId": "124c33293c43417ab7879e14c8d9eb18",
		"code":          code,
		"desc":          "Thành công",
	}
	body, err := json.Marshal(map[string]any{
		"code":      code,
		"desc":      "success",
		"success":   true,
		"data":      data,
		"signature": signData(t, data, testChecksumKey),
	})
	if err != nil {
		t.Fatalf("marshal webhook: %v", err)
	}
	return body
}

func newTestClient() *Client {
	return &Client{
		cfg:  Config{ClientID: "id", ClientSecret: "secret", ChecksumKey: testChecksumKey},
		http: &http.Client{},
	}
}

func handlerFor(t *testing.T, deliver func(ctx context.Context, e payment.Event) error) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	newTestClient().RegisterRoutes(router.New(mux, payment.WebhookPathPrefix), deliver)
	return mux
}

func TestWebhookValidSignatureDelivers(t *testing.T) {
	var got payment.Event
	delivered := false
	h := handlerFor(t, func(_ context.Context, e payment.Event) error {
		got, delivered = e, true
		return nil
	})

	body := newPayOSWebhook(t, 803347, "00")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/payos", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !delivered {
		t.Fatal("expected event to be delivered")
	}
	if got.Kind != payment.EventCharge || got.Status != payment.StatusSuccess {
		t.Fatalf("event = %+v, want charge/success", got)
	}
	if got.RefID != "803347" {
		t.Fatalf("RefID = %q, want 803347", got.RefID)
	}
}

func TestWebhookInvalidSignatureRejected(t *testing.T) {
	delivered := false
	h := handlerFor(t, func(_ context.Context, _ payment.Event) error {
		delivered = true
		return nil
	})

	body := newPayOSWebhook(t, 803347, "00")
	tampered := strings.Replace(string(body), `"amount":3000`, `"amount":9999`, 1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/payos", strings.NewReader(tampered))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if delivered {
		t.Fatal("tampered payload must not deliver an event")
	}
}

func TestWebhookNonSuccessAcked(t *testing.T) {
	delivered := false
	h := handlerFor(t, func(_ context.Context, _ payment.Event) error {
		delivered = true
		return nil
	})

	body := newPayOSWebhook(t, 803347, "01") // valid signature, not paid

	req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/payos", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (ack)", rec.Code)
	}
	if delivered {
		t.Fatal("non-success payload must not credit")
	}
}
