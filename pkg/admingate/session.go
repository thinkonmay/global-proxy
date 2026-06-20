package admingate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const cookieName = "tm_admin_sso"

var errInvalidSession = errors.New("invalid session")

// Session is an SSO admin session shared across all admin hostnames.
type Session struct {
	Email string
	Exp   time.Time
}

func signSession(email string, exp time.Time, secret []byte) (string, string, error) {
	if len(secret) == 0 {
		return "", "", errors.New("signing secret required")
	}
	payload := email + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
	return token, sig, nil
}

func parseSession(token string, secret []byte) (Session, error) {
	if token == "" || len(secret) == 0 {
		return Session{}, errInvalidSession
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return Session{}, errInvalidSession
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Session{}, errInvalidSession
	}
	payload := string(raw)
	email, expStr, ok := strings.Cut(payload, "|")
	if !ok || email == "" {
		return Session{}, errInvalidSession
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return Session{}, errInvalidSession
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return Session{}, errInvalidSession
	}
	exp := time.Unix(expUnix, 0)
	if time.Now().After(exp) {
		return Session{}, errInvalidSession
	}
	return Session{Email: email, Exp: exp}, nil
}

func sessionTTL(hours int) time.Duration {
	if hours <= 0 {
		hours = 8
	}
	return time.Duration(hours) * time.Hour
}

func formatCookie(token, domain string, ttl time.Duration) string {
	maxAge := int(ttl.Seconds())
	return fmt.Sprintf("%s=%s; Path=/; Domain=%s; Max-Age=%d; HttpOnly; Secure; SameSite=Lax",
		cookieName, token, domain, maxAge)
}
