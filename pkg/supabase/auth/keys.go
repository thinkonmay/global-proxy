package auth

import (
	"net/http"
	"strings"
)

// Group mirrors Kong ACL groups (anon, admin).
type Group int

const (
	GroupAnon Group = iota + 1
	GroupAdmin
)

// Policy controls which ACL groups may access a route.
type Policy int

const (
	// PolicyAnonAndAdmin allows anon + service_role keys (Kong rest-v1, graphql-v1).
	PolicyAnonAndAdmin Policy = iota
	// PolicyAdminOnly allows service_role keys only (Kong meta /pg).
	PolicyAdminOnly
	// PolicyStorageOptional transforms known api keys but does not require key-auth.
	PolicyStorageOptional
)

// Keys maps Supabase API keys to Kong consumer groups.
type Keys struct {
	anon  map[string]struct{}
	admin map[string]struct{}
}

func NewKeys(anonKey, publishableKey, serviceKey, secretKey string) *Keys {
	k := &Keys{
		anon:  make(map[string]struct{}),
		admin: make(map[string]struct{}),
	}
	for _, key := range []string{anonKey, publishableKey} {
		if key = strings.TrimSpace(key); key != "" {
			k.anon[key] = struct{}{}
		}
	}
	for _, key := range []string{serviceKey, secretKey} {
		if key = strings.TrimSpace(key); key != "" {
			k.admin[key] = struct{}{}
			k.anon[key] = struct{}{} // service_role is in both Kong anon+admin ACL
		}
	}
	return k
}

func (k *Keys) Lookup(key string) (Group, bool) {
	if k == nil {
		return 0, false
	}
	if _, ok := k.admin[key]; ok {
		return GroupAdmin, true
	}
	if _, ok := k.anon[key]; ok {
		return GroupAnon, true
	}
	return 0, false
}

func (k *Keys) IsKnown(key string) bool {
	_, ok := k.Lookup(key)
	return ok
}

// ExtractKey reads the Supabase apikey from headers or query (storage presign).
func ExtractKey(r *http.Request) (string, bool) {
	if k := strings.TrimSpace(r.Header.Get("apikey")); k != "" {
		return k, true
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		if k := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")); k != "" {
			return k, true
		}
	}
	if k := strings.TrimSpace(r.URL.Query().Get("apikey")); k != "" {
		return k, true
	}
	return "", false
}
