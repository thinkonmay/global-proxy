// Package testsupport provides shared test helpers for gateway handler
// packages: GoTrue JWTs and static issuer registries for node URL resolution.
package testsupport

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
)

// GoTrueJWT mints a GoTrue-style HS256 user access token for handler tests.
func GoTrueJWT(t *testing.T, secret, userID, email string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"role":  "authenticated",
		"aud":   "authenticated",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
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
