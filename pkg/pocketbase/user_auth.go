package pocketbase

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
)

const (
	tokenTypeAuth = "auth"
	usersPath     = "/api/collections/users/records/"
)

// UserAuth is the validated PocketBase users-collection identity.
type UserAuth struct {
	Email  string
	UserID string
}

// UserTokenValidator validates PocketBase user JWTs without auth-refresh.
// Valid results are cached until the token expires.
type UserTokenValidator struct {
	homeIssuer string // client-facing issuer hostname for the local cluster
	homeFetch  string // gateway-reachable base URL for the local cluster
	homeTLSName string // TLS ServerName when homeFetch host differs from issuer cert

	mu    sync.Mutex
	cache map[string]cachedUserAuth
}

type cachedUserAuth struct {
	auth UserAuth
	exp  time.Time
}

// UserTokenValidatorConfig configures token validation and home-cluster fetch routing.
type UserTokenValidatorConfig struct {
	// URL is the gateway-reachable PocketBase base for the local cluster.
	URL string
	// IssuerHost is the hostname clients send as ?issuer= for the local cluster.
	// When empty, the hostname of URL is used.
	IssuerHost string
}

func NewUserTokenValidator(cfg UserTokenValidatorConfig) *UserTokenValidator {
	homeFetch := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	homeIssuer := strings.TrimSpace(cfg.IssuerHost)
	if homeIssuer == "" {
		homeIssuer = homeFetch
	}
	tlsName := ""
	if hostFromBaseURL(homeIssuer) != hostFromBaseURL(homeFetch) {
		tlsName = hostFromBaseURL(homeIssuer)
	}
	return &UserTokenValidator{
		homeIssuer:  homeIssuer,
		homeFetch:   homeFetch,
		homeTLSName: tlsName,
		cache:       make(map[string]cachedUserAuth),
	}
}

// Validate checks the PocketBase user token and returns the record identity.
func (v *UserTokenValidator) Validate(ctx context.Context, clientIssuer, authorization string, rt http.RoundTripper) (UserAuth, error) {
	token := rawAuthToken(authorization)
	if token == "" {
		return UserAuth{}, errors.New("empty authorization token")
	}
	clientIssuer = strings.TrimRight(strings.TrimSpace(clientIssuer), "/")
	if clientIssuer == "" {
		return UserAuth{}, errors.New("missing issuer")
	}

	cacheKey := tokenCacheKey(clientIssuer, token)
	if auth, ok := v.loadCache(cacheKey); ok {
		return auth, nil
	}

	claims, err := parseAuthClaims(token)
	if err != nil {
		return UserAuth{}, err
	}
	userID, _ := claims[core.TokenClaimId].(string)

	fetchBase := v.fetchBaseURL(clientIssuer)
	auth, err := v.validateViaRecordGET(ctx, fetchBase, token, userID, rt)
	if err != nil {
		return UserAuth{}, err
	}
	v.storeCache(cacheKey, auth, claims)
	return auth, nil
}

// UserEmail validates a token and returns the user email.
func (v *UserTokenValidator) UserEmail(ctx context.Context, clientIssuer, authorization string, rt http.RoundTripper) (string, error) {
	auth, err := v.Validate(ctx, clientIssuer, authorization, rt)
	if err != nil {
		return "", err
	}
	return auth.Email, nil
}

func (v *UserTokenValidator) isHomeIssuer(clientIssuer string) bool {
	if v.homeFetch == "" {
		return false
	}
	return strings.EqualFold(hostFromBaseURL(v.homeIssuer), hostFromBaseURL(clientIssuer))
}

func (v *UserTokenValidator) fetchBaseURL(clientIssuer string) string {
	if v.homeFetch != "" && v.isHomeIssuer(clientIssuer) {
		return v.homeFetch
	}
	return clientIssuer
}

func (v *UserTokenValidator) validateViaRecordGET(ctx context.Context, baseURL, token, userID string, rt http.RoundTripper) (UserAuth, error) {
	u := strings.TrimRight(baseURL, "/") + usersPath + userID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return UserAuth{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", bearerToken(token))

	transport := rt
	if transport == nil {
		transport = http.DefaultTransport
	}
	if v.homeTLSName != "" && strings.EqualFold(hostFromBaseURL(baseURL), hostFromBaseURL(v.homeFetch)) {
		if sni := sniTransport(v.homeTLSName); sni != nil {
			transport = sni
		}
	}
	client := &http.Client{Transport: transport}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return UserAuth{}, fmt.Errorf("pocketbase record auth: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return UserAuth{}, fmt.Errorf("read record auth body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return UserAuth{}, &Error{Status: resp.StatusCode, Method: http.MethodGet, Path: usersPath + userID, Body: data}
	}
	var rec struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return UserAuth{}, fmt.Errorf("decode auth record: %w", err)
	}
	if rec.Email == "" || rec.ID == "" {
		return UserAuth{}, errors.New("invalid auth record")
	}
	if rec.ID != userID {
		return UserAuth{}, errors.New("auth record id mismatch")
	}
	return UserAuth{Email: rec.Email, UserID: rec.ID}, nil
}

func parseAuthClaims(token string) (map[string]any, error) {
	claims, err := security.ParseUnverifiedJWT(token)
	if err != nil {
		return nil, fmt.Errorf("parse pocketbase token: %w", err)
	}
	id, _ := claims[core.TokenClaimId].(string)
	collectionID, _ := claims[core.TokenClaimCollectionId].(string)
	tokenType, _ := claims[core.TokenClaimType].(string)
	if id == "" || collectionID == "" || tokenType != tokenTypeAuth {
		return nil, errors.New("missing or invalid pocketbase token claims")
	}
	return claims, nil
}

func tokenCacheKey(issuer, token string) string {
	sum := sha256.Sum256([]byte(issuer + "\n" + token))
	return hex.EncodeToString(sum[:])
}

func (v *UserTokenValidator) loadCache(key string) (UserAuth, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, ok := v.cache[key]
	if !ok || time.Now().After(entry.exp) {
		delete(v.cache, key)
		return UserAuth{}, false
	}
	return entry.auth, true
}

func (v *UserTokenValidator) storeCache(key string, auth UserAuth, claims map[string]any) {
	exp := tokenExpiry(claims)
	if exp.IsZero() {
		exp = time.Now().Add(5 * time.Minute)
	}
	v.mu.Lock()
	v.cache[key] = cachedUserAuth{auth: auth, exp: exp}
	v.mu.Unlock()
}

func tokenExpiry(claims map[string]any) time.Time {
	switch exp := claims["exp"].(type) {
	case float64:
		return time.Unix(int64(exp), 0)
	case json.Number:
		n, _ := exp.Int64()
		return time.Unix(n, 0)
	default:
		return time.Time{}
	}
}

func hostFromBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	host, _, _ := strings.Cut(u.Host, ":")
	if host == "" {
		return strings.ToLower(strings.TrimSpace(u.Host))
	}
	return strings.ToLower(host)
}

func sniTransport(serverName string) http.RoundTripper {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{ServerName: serverName}
	return tr
}
