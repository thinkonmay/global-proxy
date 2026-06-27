package routingagg

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	domainsKey = "routing:domains"
	keyPrefix  = "routing:cluster:"
)

// Entry is one VM session routed on a worker node.
type Entry struct {
	SessionID string `json:"session_id"`
	NodeHost  string `json:"node_host"`
}

// Cluster is the published routing snapshot for one cluster domain.
type Cluster struct {
	Domain   string  `json:"domain"`
	Revision int64   `json:"revision"`
	Records  []Entry `json:"records"`
}

// SyncResult is returned after a routing sync attempt.
type SyncResult struct {
	Domain   string `json:"domain"`
	Revision int64  `json:"revision"`
	Changed  bool   `json:"changed"`
}

type clusterPayload struct {
	Revision  int64   `json:"revision"`
	Signature string  `json:"signature"`
	Records   []Entry `json:"records"`
}

// Store persists hot cross-cluster routing state in Redis.
type Store struct {
	client *redis.Client
}

// NewStore connects to Redis and verifies connectivity.
func NewStore(redisURL string) (*Store, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Store{client: client}, nil
}

func (s *Store) Close() error {
	return s.client.Close()
}

func normalizeDomain(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func clusterKey(domain string) string {
	return keyPrefix + domain
}

func recordsSignature(records []Entry) string {
	normalized := normalizeRecords(records)
	payload, _ := json.Marshal(normalized)
	sum := md5.Sum(payload)
	return fmt.Sprintf("%x", sum)
}

func normalizeRecords(records []Entry) []Entry {
	out := make([]Entry, 0, len(records))
	for _, r := range records {
		id := strings.ToLower(strings.TrimSpace(r.SessionID))
		host := strings.TrimSpace(r.NodeHost)
		if id == "" || host == "" {
			continue
		}
		out = append(out, Entry{SessionID: id, NodeHost: host})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SessionID == out[j].SessionID {
			return out[i].NodeHost < out[j].NodeHost
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out
}

// Sync upserts a cluster's routing table when the VM list changes.
func (s *Store) Sync(ctx context.Context, domain string, records []Entry) (SyncResult, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return SyncResult{}, nil
	}
	records = normalizeRecords(records)
	sig := recordsSignature(records)

	key := clusterKey(domain)
	var prev clusterPayload
	if raw, err := s.client.Get(ctx, key).Bytes(); err == nil {
		_ = json.Unmarshal(raw, &prev)
	} else if err != redis.Nil {
		return SyncResult{}, err
	}

	revision := prev.Revision
	changed := false
	if sig != prev.Signature {
		revision++
		changed = true
		payload, err := json.Marshal(clusterPayload{
			Revision:  revision,
			Signature: sig,
			Records:   records,
		})
		if err != nil {
			return SyncResult{}, err
		}
		pipe := s.client.TxPipeline()
		pipe.Set(ctx, key, payload, 0)
		pipe.SAdd(ctx, domainsKey, domain)
		if _, err := pipe.Exec(ctx); err != nil {
			return SyncResult{}, err
		}
	}

	return SyncResult{
		Domain:   domain,
		Revision: revision,
		Changed:  changed,
	}, nil
}

// List returns routing snapshots for all known clusters except excludeDomain.
func (s *Store) List(ctx context.Context, excludeDomain string) ([]Cluster, error) {
	excludeDomain = normalizeDomain(excludeDomain)
	domains, err := s.client.SMembers(ctx, domainsKey).Result()
	if err != nil {
		return nil, err
	}
	sort.Strings(domains)

	var out []Cluster
	for _, domain := range domains {
		domain = normalizeDomain(domain)
		if domain == "" || (excludeDomain != "" && domain == excludeDomain) {
			continue
		}
		raw, err := s.client.Get(ctx, clusterKey(domain)).Bytes()
		if err == redis.Nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		var payload clusterPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, err
		}
		records := payload.Records
		if records == nil {
			records = []Entry{}
		}
		out = append(out, Cluster{
			Domain:   domain,
			Revision: payload.Revision,
			Records:  records,
		})
	}
	return out, nil
}
