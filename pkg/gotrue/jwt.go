// Package gotrue validates GoTrue (Supabase Auth) user JWTs at the gateway edge (Track C1/C4).
package gotrue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultAudience = "authenticated"

var (
	ErrEmptyToken   = errors.New("empty authorization token")
	ErrInvalidToken = errors.New("invalid gotrue token")
)

// UserAuth is the validated GoTrue identity from a user access token.
type UserAuth struct {
	Email  string
	UserID string
}

// JWTValidator verifies HS256 GoTrue access tokens signed with JWT_SECRET.
type JWTValidator struct {
	secret []byte

	mu    sync.Mutex
	cache map[string]cachedUserAuth
}

type cachedUserAuth struct {
	auth UserAuth
	exp  time.Time
}

// JWTValidatorConfig configures GoTrue JWT validation.
type JWTValidatorConfig struct {
	Secret string
}

// NewJWTValidator returns a validator when secret is non-empty; otherwise nil.
func NewJWTValidator(cfg JWTValidatorConfig) *JWTValidator {
	secret := strings.TrimSpace(cfg.Secret)
	if secret == "" {
		return nil
	}
	return &JWTValidator{
		secret: []byte(secret),
		cache:  make(map[string]cachedUserAuth),
	}
}

// Validate checks a Bearer token and returns the user identity.
func (v *JWTValidator) Validate(_ context.Context, authorization string) (UserAuth, error) {
	token := rawAuthToken(authorization)
	if token == "" {
		return UserAuth{}, ErrEmptyToken
	}

	cacheKey := tokenCacheKey(token)
	if auth, ok := v.loadCache(cacheKey); ok {
		return auth, nil
	}

	claims, err := v.parseClaims(token)
	if err != nil {
		return UserAuth{}, err
	}

	userID := strings.TrimSpace(fmt.Sprint(claims["sub"]))
	email, _ := claims["email"].(string)
	email = strings.TrimSpace(email)
	if userID == "" || email == "" {
		return UserAuth{}, ErrInvalidToken
	}

	auth := UserAuth{Email: email, UserID: userID}
	v.storeCache(cacheKey, auth, claims)
	return auth, nil
}

// UserEmail validates a token and returns the user email.
func (v *JWTValidator) UserEmail(authorization string) (string, error) {
	auth, err := v.Validate(context.Background(), authorization)
	if err != nil {
		return "", err
	}
	return auth.Email, nil
}

func (v *JWTValidator) parseClaims(token string) (jwt.MapClaims, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !parsed.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	role, _ := claims["role"].(string)
	if role != "" && role != defaultAudience {
		return nil, ErrInvalidToken
	}
	if aud, ok := claims["aud"].(string); ok && aud != "" && aud != defaultAudience {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func rawAuthToken(authorization string) string {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return ""
	}
	const prefix = "Bearer "
	if strings.HasPrefix(strings.ToLower(authorization), strings.ToLower(prefix)) {
		return strings.TrimSpace(authorization[len(prefix):])
	}
	return authorization
}

func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (v *JWTValidator) loadCache(key string) (UserAuth, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, ok := v.cache[key]
	if !ok || time.Now().After(entry.exp) {
		return UserAuth{}, false
	}
	return entry.auth, true
}

func (v *JWTValidator) storeCache(key string, auth UserAuth, claims jwt.MapClaims) {
	exp := time.Now().Add(time.Hour)
	if raw, ok := claims["exp"].(float64); ok {
		exp = time.Unix(int64(raw), 0)
	}
	v.mu.Lock()
	v.cache[key] = cachedUserAuth{auth: auth, exp: exp}
	v.mu.Unlock()
}
