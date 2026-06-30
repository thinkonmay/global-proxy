package metricsagg

import (
	"net/http"
	"strings"
)

const theRedCNPrefix = "the-red:"

// RequireTheRedMTLS rejects requests without a Vault-issued the-red ops client certificate.
func RequireTheRedMTLS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		cn := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.CommonName)
		if !strings.HasPrefix(cn, theRedCNPrefix) {
			http.Error(w, "the-red client certificate required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// TheRedCN builds the PKI common name for an SSO-authenticated the-red operator.
func TheRedCN(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	email = strings.ReplaceAll(email, "@", "_at_")
	return theRedCNPrefix + email
}
