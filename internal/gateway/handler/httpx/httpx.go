// Package httpx holds the gateway handlers' shared HTTP request/response
// helpers: JSON encoding, body reading, header copying, timeouts, and generic
// error rendering. It carries no domain logic and no package state, so every
// handler package can depend on it without coupling.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// WriteJSON encodes v as JSON with the given status code.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError renders {"error": msg} as JSON with the given status code.
func WriteError(w http.ResponseWriter, code int, msg string) {
	WriteJSON(w, code, map[string]string{"error": msg})
}

// WriteData renders {"data": v} as JSON with 200 OK.
func WriteData(w http.ResponseWriter, v any) {
	WriteJSON(w, http.StatusOK, map[string]any{"data": v})
}

// WriteUpstreamErr renders an upstream failure: a PostgREST error body as
// 502 Bad Gateway (trimmed), any other error as 500.
func WriteUpstreamErr(w http.ResponseWriter, err error) {
	var pe *postgrest.Error
	if errors.As(err, &pe) {
		WriteJSON(w, http.StatusBadGateway, map[string]string{"error": strings.TrimSpace(string(pe.Body))})
		return
	}
	WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

// WritePostgrestErr renders a PostgREST error body (or the raw error) as JSON.
// It returns 200 with an {"error": ...} payload to match existing client
// expectations.
func WritePostgrestErr(w http.ResponseWriter, err error) {
	var pe *postgrest.Error
	if errors.As(err, &pe) {
		WriteJSON(w, http.StatusOK, map[string]string{"error": string(pe.Body)})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"error": err.Error()})
}

// ReadJSONBody reads up to 1 MiB of the request body and unmarshals it into
// dest. An empty body is not an error.
func ReadJSONBody(r *http.Request, dest any) error {
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, dest)
}

// ContextWithTimeout derives a timeout context, defaulting a nil parent to
// context.Background().
func ContextWithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, d)
}

// CopyHeader copies src headers into dst, dropping hop-by-hop Transfer-Encoding.
func CopyHeader(dst, src http.Header) {
	for k, vals := range src {
		if strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// ClusterBaseURL normalizes a cluster reference into an https base URL.
func ClusterBaseURL(cluster string) string {
	cluster = strings.TrimSpace(cluster)
	if cluster == "" {
		return ""
	}
	if strings.HasPrefix(cluster, "http://") || strings.HasPrefix(cluster, "https://") {
		return strings.TrimRight(cluster, "/")
	}
	return "https://" + strings.TrimRight(cluster, "/")
}

// ClusterHost strips scheme and trailing slash from a cluster reference,
// leaving the bare host.
func ClusterHost(cluster string) string {
	cluster = strings.TrimSpace(cluster)
	cluster = strings.TrimPrefix(cluster, "https://")
	cluster = strings.TrimPrefix(cluster, "http://")
	return strings.TrimRight(cluster, "/")
}
