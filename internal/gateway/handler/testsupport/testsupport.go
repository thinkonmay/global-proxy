// Package testsupport provides shared test helpers for gateway handler
// packages: minting PocketBase user JWTs and building static issuer registries.
package testsupport

import (
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
)

// TestUserJWT mints a PocketBase user auth token for userID signed with the
// well-known test secret.
func TestUserJWT(t *testing.T, userID string) string {
	t.Helper()
	tok, err := security.NewJWT(map[string]any{
		core.TokenClaimId:           userID,
		core.TokenClaimCollectionId: "_pb_users_auth_",
		core.TokenClaimType:         "auth",
		core.TokenClaimRefreshable:  true,
	}, "test-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestIssuerRegistry builds a static issuer registry mapping issuerHost (or
// fetchURL when empty) to fetchURL.
func TestIssuerRegistry(fetchURL, issuerHost string) *cluster.IssuerRegistry {
	host := issuerHost
	if host == "" {
		host = fetchURL
	}
	return cluster.NewStaticIssuerRegistry(map[string]string{
		host: fetchURL,
	}, cluster.IssuerRegistryConfig{
		HomeFetch:      fetchURL,
		HomeIssuerHost: issuerHost,
	})
}
