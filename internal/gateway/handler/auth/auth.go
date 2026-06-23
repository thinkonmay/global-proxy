// Package auth owns gateway request authentication (GoTrue JWT) and the cluster
// issuer allowlist for node URL resolution. Configured once at startup via
// ConfigureAuth, then consulted by RequireUser / Validate and ResolveClusterURL.
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/gotrue"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const authTimeout = 5 * time.Second

var (
	gotrueUserAuth *gotrue.JWTValidator
	clusterIssuers *cluster.IssuerRegistry
	authPR         *postgrest.Client

	// linkedAuthUsers memoizes auth_user_id values already linked to app_user
	// this process, so link_auth_user_v1 runs at most once per user (link_cost).
	linkedAuthUsers sync.Map
)

// ConfigureAuth wires GoTrue JWT validation and the cluster issuer registry.
// Call once at gateway startup after PostgREST is available.
func ConfigureAuth(pr *postgrest.Client, pbCfg config.PocketBase, supabaseCfg config.Supabase) {
	authPR = pr
	clusterIssuers = cluster.NewIssuerRegistry(pr, cluster.IssuerRegistryConfig{
		HomeFetch:      pbCfg.URL,
		HomeIssuerHost: pbCfg.IssuerHost,
	})
	gotrueUserAuth = gotrue.NewJWTValidator(gotrue.JWTValidatorConfig{
		Secret: supabaseCfg.JWTSecret,
	})
}

// ConfigureClusterRegistry configures cluster URL resolution for tests.
func ConfigureClusterRegistry(issuers *cluster.IssuerRegistry) {
	clusterIssuers = issuers
}

// ConfigureGoTrueAuth configures GoTrue JWT validation for tests.
func ConfigureGoTrueAuth(jwtSecret string) {
	gotrueUserAuth = gotrue.NewJWTValidator(gotrue.JWTValidatorConfig{Secret: jwtSecret})
}

// IssuerFromRequest extracts the issuer query parameter (cluster routing, not auth).
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
	if errors.Is(err, cluster.ErrUnknownIssuer) {
		return "", http.StatusForbidden, "invalid cluster"
	}
	if err != nil {
		return "", http.StatusServiceUnavailable, "cluster registry unavailable"
	}
	return fetchURL, 0, ""
}

// AuthErrFromValidate maps a token-validation error to an HTTP status + message.
func AuthErrFromValidate(err error) (status int, msg string) {
	if errors.Is(err, gotrue.ErrInvalidToken) || errors.Is(err, gotrue.ErrEmptyToken) {
		return http.StatusUnauthorized, "auth failed"
	}
	return http.StatusUnauthorized, "auth failed"
}

// RequireUser validates the GoTrue JWT and returns the user email.
func RequireUser(ctx context.Context, r *http.Request, _ http.RoundTripper) (email string, ok bool, status int, msg string) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return "", false, http.StatusUnauthorized, "authorization required"
	}
	if gotrueUserAuth == nil {
		return "", false, http.StatusServiceUnavailable, "auth not configured"
	}
	ctx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	a, err := gotrueUserAuth.Validate(ctx, authHeader)
	if err != nil {
		status, msg = AuthErrFromValidate(err)
		return "", false, status, msg
	}
	linkAuthUser(ctx, a.UserID, a.Email)
	return a.Email, true, 0, ""
}

// Validate authenticates a GoTrue token and returns email and user id.
// status 0 == ok. rt is unused (kept for call-site compatibility).
func Validate(ctx context.Context, authHeader string, _ http.RoundTripper) (email, userID string, status int, msg string) {
	if gotrueUserAuth == nil {
		return "", "", http.StatusServiceUnavailable, "auth not configured"
	}
	ctx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	a, err := gotrueUserAuth.Validate(ctx, authHeader)
	if err != nil {
		status, msg = AuthErrFromValidate(err)
		return "", "", status, msg
	}
	linkAuthUser(ctx, a.UserID, a.Email)
	return a.Email, a.UserID, 0, ""
}

// linkAuthUser upserts identity.app_user for the GoTrue subject (best-effort).
// The link is stable, so it is performed at most once per auth_user_id per
// process (link_cost = cache); subsequent requests skip the RPC entirely.
func linkAuthUser(ctx context.Context, authUserID, email string) {
	if authPR == nil || authUserID == "" || email == "" {
		return
	}
	if _, done := linkedAuthUsers.Load(authUserID); done {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var appUserID int64
	if err := authPR.RPC(ctx, "link_auth_user_v1", map[string]any{
		"auth_user_id": authUserID,
		"email":        email,
	}, &appUserID); err != nil {
		return // leave uncached so a later request retries the link
	}
	linkedAuthUsers.Store(authUserID, struct{}{})
}

// WriteAuthErr renders an auth error as JSON.
func WriteAuthErr(w http.ResponseWriter, status int, msg string) {
	httpx.WriteError(w, status, msg)
}
