// Package auth owns gateway request authentication: the PocketBase user-token
// validator and the cluster issuer allowlist. The validator and registry are
// package state configured once at startup via ConfigureAuth, then consulted by
// RequireUser / Validate and by cluster-URL resolution.
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const (
	pbAuthTimeout  = 3 * time.Second
	pwaAuthTimeout = 5 * time.Second
)

var (
	pbUserAuth     *pocketbase.UserTokenValidator
	clusterIssuers *cluster.IssuerRegistry
)

// ConfigureAuth wires cluster issuer allowlisting and PocketBase user-token validation.
// Call once at gateway startup after PostgREST is available.
func ConfigureAuth(pr *postgrest.Client, pbCfg config.PocketBase) {
	clusterIssuers = cluster.NewIssuerRegistry(pr, cluster.IssuerRegistryConfig{
		HomeFetch:      pbCfg.URL,
		HomeIssuerHost: pbCfg.IssuerHost,
	})
	pbUserAuth = pocketbase.NewUserTokenValidator(pocketbase.UserTokenValidatorConfig{
		Issuers: clusterIssuers,
	})
}

// ConfigurePocketBaseAuth configures auth for tests with a static issuer registry.
func ConfigurePocketBaseAuth(pbCfg config.PocketBase, issuers *cluster.IssuerRegistry) {
	clusterIssuers = issuers
	pbUserAuth = pocketbase.NewUserTokenValidator(pocketbase.UserTokenValidatorConfig{
		Issuers: issuers,
	})
}

// IssuerFromRequest extracts the issuer query parameter.
func IssuerFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("issuer"))
}

// ResolveClusterURL maps an issuer reference to a fetch URL via the registry,
// returning an HTTP status + message on failure (status 0 == ok).
func ResolveClusterURL(ctx context.Context, raw string) (string, int, string) {
	if clusterIssuers == nil {
		return strings.TrimRight(strings.TrimSpace(raw), "/"), 0, ""
	}
	fetchURL, err := clusterIssuers.FetchURL(ctx, raw)
	if errors.Is(err, pocketbase.ErrUnknownIssuer) {
		return "", http.StatusForbidden, "invalid cluster"
	}
	if err != nil {
		return "", http.StatusServiceUnavailable, "cluster registry unavailable"
	}
	return fetchURL, 0, ""
}

// AuthErrFromValidate maps a token-validation error to an HTTP status + message.
func AuthErrFromValidate(err error) (status int, msg string) {
	if errors.Is(err, pocketbase.ErrUnknownIssuer) {
		return http.StatusForbidden, "invalid issuer"
	}
	return http.StatusUnauthorized, "pocketbase auth failed"
}

// RequireUser validates the PocketBase token against the issuer node and returns the record email.
func RequireUser(ctx context.Context, r *http.Request, rt http.RoundTripper) (email string, ok bool, status int, msg string) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return "", false, http.StatusUnauthorized, "authorization required"
	}
	issuer := IssuerFromRequest(r)
	if issuer == "" {
		return "", false, http.StatusBadRequest, "issuer query required"
	}
	ctx, cancel := context.WithTimeout(ctx, pbAuthTimeout)
	defer cancel()
	recordEmail, err := pbUserAuth.UserEmail(ctx, issuer, authHeader, rt)
	if err != nil {
		status, msg = AuthErrFromValidate(err)
		return "", false, status, msg
	}
	return recordEmail, true, 0, ""
}

// Validate authenticates a token for the given issuer and returns the record's
// email and user id. It performs no header/issuer presence checks — callers
// that need bespoke messages should validate those first. status 0 == ok.
func Validate(ctx context.Context, issuer, authHeader string, rt http.RoundTripper) (email, userID string, status int, msg string) {
	ctx, cancel := context.WithTimeout(ctx, pwaAuthTimeout)
	defer cancel()
	a, err := pbUserAuth.Validate(ctx, issuer, authHeader, rt)
	if err != nil {
		status, msg = AuthErrFromValidate(err)
		return "", "", status, msg
	}
	return a.Email, a.UserID, 0, ""
}

// WriteAuthErr renders an auth error as JSON.
func WriteAuthErr(w http.ResponseWriter, status int, msg string) {
	httpx.WriteError(w, status, msg)
}
