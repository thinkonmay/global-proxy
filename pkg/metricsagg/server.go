package metricsagg

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Server accepts virtdaemon push POSTs and serves merged Prometheus text from the cache layer.
type Server struct {
	cache *Cache
}

func NewServer(cache *Cache) *Server {
	return &Server{cache: cache}
}

func (s *Server) ScrapeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/internal/nodes", s.handleInternalNodes)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// HandlePush ingests a metrics push (protected by mTLS at the gateway edge).
func (s *Server) HandlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	node := strings.TrimSpace(r.Header.Get("node"))
	pushType := strings.TrimSpace(r.Header.Get("type"))
	if node == "" || pushType == "" {
		http.Error(w, "missing node or type header", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.cache.SavePush(ctx, node, pushType, body); err != nil {
		slog.Error("metrics push", "node", node, "type", pushType, "err", err)
		http.Error(w, "cache write failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleInternalNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	nodes, err := s.cache.ListNodeInfo(ctx)
	if err != nil {
		slog.Error("internal nodes", "err", err)
		http.Error(w, "cache read failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	type row struct {
		Node  string          `json:"node"`
		Stale bool            `json:"stale"`
		Info  json.RawMessage `json:"info,omitempty"`
	}
	out := make([]row, 0, len(nodes))
	for _, n := range nodes {
		item := row{Node: n.Node, Stale: n.Stale}
		if len(n.Info) > 0 && !n.Stale {
			item.Info = json.RawMessage(n.Info)
		}
		out = append(out, item)
	}
	_ = enc.Encode(out)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	body, err := s.cache.MergedExposition(ctx)
	if err != nil {
		slog.Error("metrics scrape", "err", err)
		http.Error(w, "cache read failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(body)
}
