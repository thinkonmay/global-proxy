package auth

import (
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

// RequireKey validates apikey (Kong key-auth + ACL) and sets Authorization Bearer.
func RequireKey(keys *Keys, policy Policy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, ok := ExtractKey(r)
			if !ok {
				if policy == PolicyStorageOptional {
					clearEmptyAuthorization(r)
					next.ServeHTTP(w, r)
					return
				}
				writeJSON(w, http.StatusUnauthorized, `{"message":"No API key found in request"}`)
				return
			}
			group, valid := keys.Lookup(key)
			if !valid {
				writeJSON(w, http.StatusUnauthorized, `{"message":"Invalid API key"}`)
				return
			}
			if policy == PolicyAdminOnly && group != GroupAdmin {
				writeJSON(w, http.StatusForbidden, `{"message":"You cannot consume this service"}`)
				return
			}
			r.Header.Set("apikey", key)
			r.Header.Set("Authorization", "Bearer "+key)
			next.ServeHTTP(w, r)
		})
	}
}

// StorageAuth applies Kong storage request-transformer behavior without key-auth.
func StorageAuth(keys *Keys) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if key, ok := ExtractKey(r); ok && keys.IsKnown(key) {
				r.Header.Set("apikey", key)
				r.Header.Set("Authorization", "Bearer "+key)
			}
			clearEmptyAuthorization(r)
			next.ServeHTTP(w, r)
		})
	}
}

func clearEmptyAuthorization(r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" || auth == "Bearer" {
		r.Header.Del("Authorization")
	}
}
