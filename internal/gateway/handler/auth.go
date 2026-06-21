package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const pbAuthTimeout = 3 * time.Second

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

func issuerFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("issuer"))
}

func resolveClusterURL(ctx context.Context, raw string) (string, int, string) {
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

func authErrFromValidate(err error) (status int, msg string) {
	if errors.Is(err, pocketbase.ErrUnknownIssuer) {
		return http.StatusForbidden, "invalid issuer"
	}
	return http.StatusUnauthorized, "pocketbase auth failed"
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
		status, msg = authErrFromValidate(err)
		return "", false, status, msg
	}
	return recordEmail, true, 0, ""
}

func writeAuthErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
