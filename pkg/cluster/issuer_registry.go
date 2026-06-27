package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// ErrUnknownIssuer is returned when ?issuer= / cluster= is not in infra.clusters.
var ErrUnknownIssuer = errors.New("unknown cluster issuer")

// IssuerRegistry resolves client ?issuer=/cluster= values to trusted cluster API bases
// loaded from the active rows in infra.clusters (via PostgREST).
type IssuerRegistry struct {
	pr             *postgrest.Client
	homeFetch      string
	homeIssuerHost string
	ttl            time.Duration

	mu       sync.RWMutex
	byHost   map[string]issuerEntry
	loadedAt time.Time
}

type issuerEntry struct {
	ID       int64
	Domain   string
	FetchURL string
}

// IssuerRegistryConfig tunes home-cluster Docker reachability overrides.
type IssuerRegistryConfig struct {
	// HomeFetch is the gateway-reachable API base for the local cluster.
	HomeFetch string
	// HomeIssuerHost is the public hostname clients send for the local cluster.
	HomeIssuerHost string
	TTL            time.Duration
}

func NewIssuerRegistry(pr *postgrest.Client, cfg IssuerRegistryConfig) *IssuerRegistry {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	return &IssuerRegistry{
		pr:             pr,
		homeFetch:      strings.TrimRight(strings.TrimSpace(cfg.HomeFetch), "/"),
		homeIssuerHost: strings.TrimSpace(cfg.HomeIssuerHost),
		ttl:            cfg.TTL,
		byHost:         make(map[string]issuerEntry),
	}
}

// NewStaticIssuerRegistry builds an in-memory registry for tests.
func NewStaticIssuerRegistry(hostToFetch map[string]string, cfg IssuerRegistryConfig) *IssuerRegistry {
	r := NewIssuerRegistry(nil, cfg)
	byHost := make(map[string]issuerEntry, len(hostToFetch))
	for host, fetch := range hostToFetch {
		h := NormalizeHost(host)
		if h == "" {
			continue
		}
		byHost[h] = issuerEntry{Domain: host, FetchURL: strings.TrimRight(fetch, "/")}
	}
	r.byHost = byHost
	r.loadedAt = time.Now()
	return r
}

// FetchURL returns the trusted cluster API base URL for a client issuer/cluster value.
func (r *IssuerRegistry) FetchURL(ctx context.Context, clientIssuer string) (string, error) {
	if err := r.ensureLoaded(ctx); err != nil {
		return "", err
	}
	host := NormalizeHost(clientIssuer)
	if host == "" {
		return "", ErrUnknownIssuer
	}
	r.mu.RLock()
	entry, ok := r.byHost[host]
	r.mu.RUnlock()
	if !ok {
		return "", ErrUnknownIssuer
	}
	fetch := entry.FetchURL
	if r.homeFetch != "" && r.homeIssuerHost != "" &&
		strings.EqualFold(host, NormalizeHost(r.homeIssuerHost)) {
		fetch = r.homeFetch
	}
	if fetch == "" {
		return "", ErrUnknownIssuer
	}
	return fetch, nil
}

func (r *IssuerRegistry) ensureLoaded(ctx context.Context) error {
	r.mu.RLock()
	fresh := r.pr == nil || (len(r.byHost) > 0 && time.Since(r.loadedAt) < r.ttl)
	r.mu.RUnlock()
	if fresh {
		return nil
	}
	return r.reload(ctx)
}

func (r *IssuerRegistry) reload(ctx context.Context) error {
	if r.pr == nil {
		return ErrUnknownIssuer
	}
	var rows []struct {
		ID     int64           `json:"id"`
		Domain string          `json:"domain"`
		Secret json.RawMessage `json:"secret"`
		Active *bool           `json:"active"`
	}
	q := url.Values{}
	q.Set("select", "id,domain,secret")
	q.Set("active", "eq.true")
	if err := r.pr.SelectService(ctx, "clusters", q, &rows); err != nil {
		return err
	}
	byHost := make(map[string]issuerEntry, len(rows))
	for _, row := range rows {
		if row.Active != nil && !*row.Active {
			continue
		}
		domain := strings.TrimSpace(row.Domain)
		host := NormalizeHost(domain)
		if host == "" {
			continue
		}
		fetch := defaultFetchURL(domain)
		if sec, err := ParseSecret(row.Secret); err == nil && sec.URL != "" {
			fetch = sec.URL
		}
		byHost[host] = issuerEntry{
			ID:       row.ID,
			Domain:   domain,
			FetchURL: strings.TrimRight(fetch, "/"),
		}
	}
	r.mu.Lock()
	r.byHost = byHost
	r.loadedAt = time.Now()
	r.mu.Unlock()
	return nil
}

func defaultFetchURL(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimRight(domain, "/")
	if domain == "" {
		return ""
	}
	return "https://" + domain
}

// NormalizeHost extracts a lowercase hostname from a domain or URL string.
func NormalizeHost(raw string) string {
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
