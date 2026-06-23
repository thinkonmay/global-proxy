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

// PWAAuthFromRequest validates the request's Authorization header (GoTrue JWT)
// and returns the resolved identity. status 0 == ok.
func PWAAuthFromRequest(ctx context.Context, rt http.RoundTripper, r *http.Request) (PWAUserAuth, int, string) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return PWAUserAuth{}, http.StatusUnauthorized, "Unauthorized: No auth header"
	}
	email, userID, status, msg := Validate(ctx, authHeader, rt)
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
