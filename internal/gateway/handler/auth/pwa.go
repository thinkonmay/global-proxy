package auth

import (
	"context"
	"net/http"
	"strings"
)

// PWAUser is the authenticated subject for legacy /api/pwa/* routes.
type PWAUser struct {
	Email  string
	UserID string
}

// PWAAuthFromRequest validates the GoTrue JWT on a PWA request.
func PWAAuthFromRequest(ctx context.Context, rt http.RoundTripper, r *http.Request) (PWAUser, int, string) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return PWAUser{}, http.StatusUnauthorized, "Unauthorized: No auth header"
	}
	email, userID, status, msg := ValidateRequest(ctx, r, rt)
	if status != 0 {
		if status == http.StatusUnauthorized {
			return PWAUser{}, http.StatusUnauthorized, "Unauthorized: Invalid token"
		}
		return PWAUser{}, status, msg
	}
	return PWAUser{Email: email, UserID: userID}, 0, ""
}

// PWAEmailMatch ensures the JWT subject matches a body/query email field.
func PWAEmailMatch(usr PWAUser, email string) (int, string) {
	if strings.EqualFold(strings.TrimSpace(usr.Email), strings.TrimSpace(email)) {
		return 0, ""
	}
	return http.StatusForbidden, "Unauthorized: Email mismatch"
}
