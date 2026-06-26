// Package payermax implements tests for the payment.Client interface for the PayerMax provider.
package payermax

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

func TestParseRedirectURL(t *testing.T) {
	resp := `{"code":"APPLY_SUCCESS","data":{"redirectUrl":"https://pay.x/abc","outTradeNo":"P9"}}`
	url, err := parseRedirectURL([]byte(resp))
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://pay.x/abc" {
		t.Fatalf("url = %q", url)
	}
}

func TestOrderFieldsTargetOrg(t *testing.T) {
	base := payment.ChargeParams{IdempotencyKey: "9", Money: payment.Money{Amount: 1000, Currency: "IDR"}}

	// No method → no targetOrg; hosted page lets the user pick.
	if f := orderFields(base, "IDR", "P9"); f["targetOrg"] != "" {
		t.Fatalf("targetOrg should be absent, got %q", f["targetOrg"])
	}

	// Method is normalized to upper-case and routed to targetOrg.
	withMethod := base
	withMethod.Method = "ovo"
	if f := orderFields(withMethod, "IDR", "P9"); f["targetOrg"] != "OVO" {
		t.Fatalf("targetOrg = %q, want OVO", f["targetOrg"])
	}
}

// genKey returns a fresh RSA key as bare-base64 PKCS#8 private + PKIX public strings.
func genKey(t *testing.T) (priv, pub string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(pubDER)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	privB64, pubB64 := genKey(t)
	priv, err := parsePrivateKey(privB64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parsePublicKey(pubB64)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"hello":"world"}`)
	sig, err := signRSA(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRSA(body, sig, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := verifyRSA([]byte(`{"hello":"tampered"}`), sig, pub); err == nil {
		t.Fatal("expected verify failure on tampered body")
	}
}

// webhookHandler builds a PayerMax client with the given keys and returns its
// mounted webhook mux plus a pointer that captures the delivered event.
func webhookHandler(t *testing.T, priv, pub string, deliverErr error) (http.Handler, *payment.Event, *bool) {
	t.Helper()
	c := New(Config{AppID: "app", MerchantNo: "m1", PrivateKey: priv, PublicKey: pub}).(*Client)
	var got payment.Event
	delivered := false
	mux := http.NewServeMux()
	c.RegisterRoutes(router.New(mux, payment.WebhookPathPrefix), func(_ context.Context, e payment.Event) error {
		got, delivered = e, true
		return deliverErr
	})
	return mux, &got, &delivered
}

func signBody(t *testing.T, privB64 string, body []byte) string {
	t.Helper()
	priv, err := parsePrivateKey(privB64)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signRSA(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func postWebhook(h http.Handler, body []byte, sign string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, payment.WebhookPathPrefix+"/payermax", bytes.NewReader(body))
	req.Header.Set("sign", sign)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWebhookSettlesPaid(t *testing.T) {
	priv, pub := genKey(t)
	h, got, delivered := webhookHandler(t, priv, pub, nil)

	body := []byte(`{"notifyType":"PAYMENT","data":{"outTradeNo":"P42","status":"SUCCESS"}}`)
	rec := postWebhook(h, body, signBody(t, priv, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// outTradeNo "P42" → settle keys on numeric txn id "42".
	if !*delivered || got.RefID != "42" || got.ProviderID != "P42" || got.Status != payment.StatusSuccess {
		t.Fatalf("event = %+v delivered=%v", *got, *delivered)
	}
}

func TestWebhookRejectsBadSignature(t *testing.T) {
	priv, pub := genKey(t)
	h, _, delivered := webhookHandler(t, priv, pub, nil)

	body := []byte(`{"data":{"outTradeNo":"P42","status":"SUCCESS"}}`)
	sig := signBody(t, priv, body)
	rec := postWebhook(h, []byte(`{"data":{"outTradeNo":"P42","status":"SUCCESS","x":1}}`), sig)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if *delivered {
		t.Fatal("tampered payload must not deliver")
	}
}

func TestWebhookPendingAcked(t *testing.T) {
	priv, pub := genKey(t)
	h, _, delivered := webhookHandler(t, priv, pub, nil)

	body := []byte(`{"data":{"outTradeNo":"P42","status":"PENDING"}}`)
	rec := postWebhook(h, body, signBody(t, priv, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (ack)", rec.Code)
	}
	if *delivered {
		t.Fatal("pending must not settle")
	}
}

func TestParseKeyAcceptsPEM(t *testing.T) {
	privB64, _ := genKey(t)
	der, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := parsePrivateKey(string(pemKey)); err != nil {
		t.Fatalf("PEM private key should parse: %v", err)
	}
}

// TestCharge_SignsAndParses runs a full Charge against a stub gateway that asserts the
// envelope, verifies the request signature with the merchant public key, and replies signed.
func TestCharge_SignsAndParses(t *testing.T) {
	privB64, pubB64 := genKey(t)
	merchantPub, err := parsePublicKey(pubB64)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := verifyRSA(body, r.Header.Get("sign"), merchantPub); err != nil {
			t.Errorf("request signature invalid: %v", err)
		}
		var env struct {
			Version    string            `json:"version"`
			AppID      string            `json:"appId"`
			MerchantNo string            `json:"merchantNo"`
			Data       map[string]string `json:"data"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Errorf("envelope unmarshal: %v", err)
		}
		if env.Version != "1.4" || env.AppID != "app" || env.MerchantNo != "m1" {
			t.Errorf("envelope = %+v", env)
		}
		if env.Data["outTradeNo"] != "P42" {
			t.Errorf("outTradeNo = %q", env.Data["outTradeNo"])
		}
		w.Write([]byte(`{"code":"APPLY_SUCCESS","data":{"redirectUrl":"https://pay.x/go"}}`))
	}))
	defer srv.Close()

	c := New(Config{AppID: "app", MerchantNo: "m1", BaseURL: srv.URL, PrivateKey: privB64})
	ch, err := c.Charge(context.Background(), payment.ChargeParams{
		IdempotencyKey: "42",
		Money:          payment.Money{Amount: 1000, Currency: "IDR"},
		ReturnURL:      "https://thinkmay.net/return",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ch.ID != "P42" || ch.RedirectURL != "https://pay.x/go" || ch.Status != payment.StatusPending {
		t.Fatalf("charge = %+v", ch)
	}
}
