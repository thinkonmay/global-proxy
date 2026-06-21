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

var pbIssuerResolver pocketbase.IssuerResolver

// ConfigurePocketBaseAuth sets the issuer→internal URL resolver for user token
// verification (auth-refresh). Call once at gateway startup.
func ConfigurePocketBaseAuth(cfg config.PocketBase) {
	pbIssuerResolver = pocketbase.NewIssuerResolver(cfg.URL, cfg.InternalURL)
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
	recordEmail, err := pocketbase.UserEmailFromRefresh(ctx, pbIssuerResolver, issuer, authHeader, rt)
	if err != nil {
		return "", false, http.StatusUnauthorized, "pocketbase auth refresh failed"
	}
	return recordEmail, true, 0, ""
}

func writeAuthErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
