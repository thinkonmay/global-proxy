package gotrue

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testGoTrueJWT(t *testing.T, secret, userID, email string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"role":  "authenticated",
		"aud":   "authenticated",
		"exp":   exp.Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestJWTValidatorAcceptsUserToken(t *testing.T) {
	const secret = "test-jwt-secret"
	v := NewJWTValidator(JWTValidatorConfig{Secret: secret})
	tok := testGoTrueJWT(t, secret, "550e8400-e29b-41d4-a716-446655440000", "user@example.com", time.Now().Add(time.Hour))

	auth, err := v.Validate(context.Background(), "Bearer "+tok)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Email != "user@example.com" || auth.UserID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("auth = %+v", auth)
	}
}

func TestJWTValidatorRejectsWrongSecret(t *testing.T) {
	v := NewJWTValidator(JWTValidatorConfig{Secret: "right-secret"})
	tok := testGoTrueJWT(t, "wrong-secret", "u1", "user@example.com", time.Now().Add(time.Hour))

	_, err := v.Validate(context.Background(), "Bearer "+tok)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestJWTValidatorRejectsServiceRole(t *testing.T) {
	const secret = "test-jwt-secret"
	v := NewJWTValidator(JWTValidatorConfig{Secret: secret})
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  "svc",
		"role": "service_role",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Validate(nil, "Bearer "+s)
	if err == nil {
		t.Fatal("expected error for service_role token")
	}
}

func TestNewJWTValidatorNilWhenSecretEmpty(t *testing.T) {
	if NewJWTValidator(JWTValidatorConfig{}) != nil {
		t.Fatal("expected nil validator")
	}
}
