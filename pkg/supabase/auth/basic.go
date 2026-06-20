package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// BasicAuth protects Studio (Kong dashboard-v1 basic-auth).
func BasicAuth(user, pass string) func(http.Handler) http.Handler {
	user = strings.TrimSpace(user)
	pass = strings.TrimSpace(pass)
	if user == "" && pass == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok ||
				subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
				subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Supabase Studio"`)
				writeJSON(w, http.StatusUnauthorized, `{"message":"Unauthorized"}`)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
