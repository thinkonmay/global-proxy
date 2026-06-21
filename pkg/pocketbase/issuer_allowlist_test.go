package pocketbase

import (
	"context"
	"strings"
)

type staticIssuerAllowlist struct {
	byHost     map[string]string
	homeFetch  string
	homeIssuer string
}

func newStaticIssuerAllowlist(hostToFetch map[string]string, homeFetch, homeIssuer string) IssuerAllowlist {
	byHost := make(map[string]string, len(hostToFetch))
	for host, fetch := range hostToFetch {
		if h := normalizeHost(host); h != "" {
			byHost[h] = strings.TrimRight(fetch, "/")
		}
	}
	return &staticIssuerAllowlist{
		byHost:     byHost,
		homeFetch:  strings.TrimRight(strings.TrimSpace(homeFetch), "/"),
		homeIssuer: strings.TrimSpace(homeIssuer),
	}
}

func (s *staticIssuerAllowlist) FetchURL(_ context.Context, clientIssuer string) (string, error) {
	host := normalizeHost(clientIssuer)
	if host == "" {
		return "", ErrUnknownIssuer
	}
	fetch, ok := s.byHost[host]
	if !ok {
		return "", ErrUnknownIssuer
	}
	if s.homeFetch != "" && s.homeIssuer != "" && host == normalizeHost(s.homeIssuer) {
		fetch = s.homeFetch
	}
	if fetch == "" {
		return "", ErrUnknownIssuer
	}
	return fetch, nil
}
