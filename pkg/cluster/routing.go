package cluster

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/routingagg"
)

// RoutingEntry is one VM session routed on a worker node.
type RoutingEntry struct {
	SessionID string `json:"session_id"`
	NodeHost  string `json:"node_host"`
}

// RoutingCluster is the published routing snapshot for one cluster.
type RoutingCluster struct {
	Domain   string         `json:"domain"`
	Revision int64          `json:"revision"`
	Records  []RoutingEntry `json:"records"`
}

// SyncRoutingResult is returned by a routing sync.
type SyncRoutingResult struct {
	Domain   string `json:"domain"`
	Revision int64  `json:"revision"`
	Changed  bool   `json:"changed"`
}

func toAggEntries(records []RoutingEntry) []routingagg.Entry {
	out := make([]routingagg.Entry, len(records))
	for i, r := range records {
		out[i] = routingagg.Entry{SessionID: r.SessionID, NodeHost: r.NodeHost}
	}
	return out
}

func fromAggClusters(clusters []routingagg.Cluster) []RoutingCluster {
	out := make([]RoutingCluster, len(clusters))
	for i, c := range clusters {
		records := make([]RoutingEntry, len(c.Records))
		for j, r := range c.Records {
			records[j] = RoutingEntry{SessionID: r.SessionID, NodeHost: r.NodeHost}
		}
		out[i] = RoutingCluster{
			Domain:   c.Domain,
			Revision: c.Revision,
			Records:  records,
		}
	}
	return out
}

// SyncRouting upserts a cluster's routing table when the VM list changes.
func SyncRouting(ctx context.Context, store *routingagg.Store, domain string, records []RoutingEntry) (SyncRoutingResult, error) {
	domain = NormalizeHost(domain)
	if domain == "" {
		return SyncRoutingResult{}, nil
	}
	result, err := store.Sync(ctx, domain, toAggEntries(records))
	if err != nil {
		return SyncRoutingResult{}, err
	}
	return SyncRoutingResult{
		Domain:   result.Domain,
		Revision: result.Revision,
		Changed:  result.Changed,
	}, nil
}

// ListRouting returns routing snapshots for all active clusters except excludeDomain.
func ListRouting(ctx context.Context, store *routingagg.Store, excludeDomain string) ([]RoutingCluster, error) {
	clusters, err := store.List(ctx, NormalizeHost(excludeDomain))
	if err != nil {
		return nil, err
	}
	return fromAggClusters(clusters), nil
}

// RoutingEntriesFromJSON extracts routing rows from a WorkerInfor JSON body (local node only).
func RoutingEntriesFromJSON(body []byte, nodeHost string) []RoutingEntry {
	nodeHost = strings.TrimSpace(nodeHost)
	if nodeHost == "" || len(body) == 0 {
		return nil
	}
	var info struct {
		Sessions []struct {
			ID string `json:"id"`
			VM *struct {
				Hostname string `json:"Hostname"`
			} `json:"vm"`
		} `json:"Sessions"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}
	var out []RoutingEntry
	for _, s := range info.Sessions {
		id := strings.TrimSpace(s.ID)
		if id == "" || s.VM == nil {
			continue
		}
		host := strings.TrimSpace(s.VM.Hostname)
		if host == "" {
			host = nodeHost
		}
		out = append(out, RoutingEntry{SessionID: id, NodeHost: host})
	}
	return out
}
