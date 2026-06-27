package metricsagg

import (
	"net/http"
)

// RequireVirtdaemonMTLS rejects requests without a verified client certificate.
// The gateway TLS listener must use tls.VerifyClientCertIfGiven with the Vault PKI CA.
func RequireVirtdaemonMTLS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
