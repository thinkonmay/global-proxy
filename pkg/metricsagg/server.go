package metricsagg

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Server accepts virtdaemon push POSTs and serves merged Prometheus text from the cache layer.
type Server struct {
	cache        *Cache
	ingestSecret string
}

func NewServer(cache *Cache, ingestSecret string) *Server {
	return &Server{cache: cache, ingestSecret: strings.TrimSpace(ingestSecret)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/", s.handlePush)
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

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.ingestSecret == "" {
		http.Error(w, "ingest not configured", http.StatusServiceUnavailable)
		return
	}
	if got := strings.TrimSpace(r.Header.Get("Authorization")); got != s.ingestSecret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
