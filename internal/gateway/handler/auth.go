package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
)

const pbAuthTimeout = 3 * time.Second

var pbUserAuth *pocketbase.UserTokenValidator

// ConfigurePocketBaseAuth sets the cached PocketBase user-token validator.
// Call once at gateway startup.
func ConfigurePocketBaseAuth(cfg config.PocketBase) {
	pbUserAuth = pocketbase.NewUserTokenValidator(pocketbase.UserTokenValidatorConfig{
		URL:        cfg.URL,
		IssuerHost: cfg.IssuerHost,
	})
}

func issuerFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("issuer"))
}

// requireUser validates the PocketBase token against the issuer node and returns the record email.
func requireUser(ctx context.Context, r *http.Request, rt http.RoundTripper) (email string, ok bool, status int, msg string) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return "", false, http.StatusUnauthorized, "authorization required"
	}
	issuer := issuerFromRequest(r)
	if issuer == "" {
		return "", false, http.StatusBadRequest, "issuer query required"
	}
	ctx, cancel := context.WithTimeout(ctx, pbAuthTimeout)
	defer cancel()
	recordEmail, err := pbUserAuth.UserEmail(ctx, issuer, authHeader, rt)
	if err != nil {
		return "", false, http.StatusUnauthorized, "pocketbase auth failed"
	}
	return recordEmail, true, 0, ""
}

func writeAuthErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
