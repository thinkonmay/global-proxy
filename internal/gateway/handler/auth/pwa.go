package auth

import (
	"context"
	"net/http"
	"strings"
)

// PWAUserAuth is the authenticated identity resolved for a PWA request.
type PWAUserAuth struct {
	Email  string
	UserID string
}

// PWAAuthFromRequest validates the request's Authorization header against the
// given issuer and returns the resolved identity. status 0 == ok. It produces
// PWA-specific messages for missing header/issuer.
func PWAAuthFromRequest(ctx context.Context, rt http.RoundTripper, r *http.Request, issuer string) (PWAUserAuth, int, string) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return PWAUserAuth{}, http.StatusUnauthorized, "Unauthorized: No auth header"
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return PWAUserAuth{}, http.StatusBadRequest, "Missing issuer"
	}
	email, userID, status, msg := Validate(ctx, issuer, authHeader, rt)
	if status != 0 {
		return PWAUserAuth{}, status, msg
	}
	return PWAUserAuth{Email: email, UserID: userID}, 0, ""
}

// PWAEmailMatch checks that the authenticated identity matches the supplied email.
func PWAEmailMatch(a PWAUserAuth, email string) (int, string) {
	if email == "" {
		return http.StatusBadRequest, "Missing email"
	}
	if !strings.EqualFold(a.Email, email) {
		return http.StatusForbidden, "Unauthorized: Email mismatch"
	}
	return 0, ""
}
