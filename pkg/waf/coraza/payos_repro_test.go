package coraza

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Reproduce a realistic PayOS webhook POST through the WAF (OWASP CRS on),
// path NOT in SkipPaths, to observe the status code the WAF returns.
func TestPayOSWebhookThroughWAF(t *testing.T) {
	m, err := New(DefaultConfig()) // Enabled + OWASPCRS true
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	reached := false
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	const body = `{"code":"00","desc":"success","success":true,"data":{"orderCode":123,"amount":3000,"description":"VQRIO123","accountNumber":"12345678","reference":"TF230204212323","transactionDateTime":"2023-02-04 18:25:00","currency":"VND","paymentLinkId":"124c33293c43417ab7879e14c8d9eb18","code":"00","desc":"Thành công","counterAccountBankId":"","counterAccountBankName":"","counterAccountName":"","counterAccountNumber":"","virtualAccountName":"","virtualAccountNumber":""},"signature":"412e915d2871504ed31be63c8f62a149a4410d34c4c42affc9006ef9917eaa03"}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/payment/webhook/payos", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "") // PayOS server often sends no/empty UA
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	t.Logf("status=%d reached_handler=%v body=%q", rec.Code, reached, rec.Body.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("WAF blocked PayOS webhook: status=%d (handler reached=%v)", rec.Code, reached)
	}
}
