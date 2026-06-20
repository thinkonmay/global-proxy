package admingate

import (
	"testing"
	"time"
)

func TestSignAndParseSession(t *testing.T) {
	secret := []byte("test-secret")
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	token, _, err := signSession("ops@thinkmay.net", exp, secret)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := parseSession(token, secret)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Email != "ops@thinkmay.net" {
		t.Fatalf("email=%q", sess.Email)
	}
}

func TestParseSessionRejectsTamper(t *testing.T) {
	secret := []byte("test-secret")
	exp := time.Now().Add(time.Hour)
	token, _, _ := signSession("ops@thinkmay.net", exp, secret)
	if _, err := parseSession(token+"x", secret); err == nil {
		t.Fatal("expected tamper rejection")
	}
}
