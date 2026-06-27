package upstream

import (
	"net"
	"net/http"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

const (
	restPrefix    = "/rest/v1"
	graphqlPath   = "/graphql/v1"
	storagePrefix = "/storage/v1"
	metaPrefix    = "/pg"
)

var removedStackMsg = []byte(`{"message":"GoTrue, Realtime, and Edge Functions are not deployed in this stack"}`)
var removedPublicRPCMsg = []byte(`{"error":"RPC endpoints are not exposed on the public gateway; use /v1/* controllers"}`)
var internalOnlySupabaseMsg = []byte(`{"message":"Supabase data APIs are internal-only; use /v1/* controllers on the public gateway"}`)

// RegisterKong mounts public-edge Supabase-related routes on thinkmay-gateway.
// Internal Kong (compose network) serves /rest/v1, /storage/v1, and /pg for
// Studio and backend services; the public hostname does not proxy them (D22).
func RegisterKong(mux *http.ServeMux, cfg *config.Config, rt http.RoundTripper) {
	registerRemovedPublicRPCRoutes(mux)

	gotrueEnabled := registerGoTrueRoute(mux, cfg, rt)
	registerDeniedInternalSupabasePaths(mux)
	registerRemovedRoutes(mux, gotrueEnabled)
	registerBlockedRoutes(mux)
}

func registerDeniedInternalSupabasePaths(mux *http.ServeMux) {
	serve := http.HandlerFunc(serveInternalOnlySupabase)
	mux.Handle(restPrefix+"/", serve)
	mux.Handle(graphqlPath, serve)
	mux.Handle(storagePrefix+"/", serve)
	mux.Handle(metaPrefix+"/", serve)
}

func serveInternalOnlySupabase(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(internalOnlySupabaseMsg)
}

func registerRemovedPublicRPCRoutes(mux *http.ServeMux) {
	serve := http.HandlerFunc(servePublicRPCRemoved)
	router.V1(mux).POST("/rpc", serve) // /v1/rpc (+ trailing-slash alias)
	mux.Handle(restPrefix+"/rpc", serve)
	mux.Handle(restPrefix+"/rpc/", serve)
}

func servePublicRPCRemoved(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(removedPublicRPCMsg)
}

func registerRemovedRoutes(mux *http.ServeMux, gotrueEnabled bool) {
	removed := []string{
		"/realtime/v1/",
		"/functions/v1/",
		"/analytics/v1/",
	}
	if !gotrueEnabled {
		removed = append([]string{"/auth/v1/"}, removed...)
	}
	for _, prefix := range removed {
		mux.Handle(prefix, http.HandlerFunc(serveRemovedStack))
	}
}

func registerBlockedRoutes(mux *http.ServeMux) {
	mux.Handle("/api/mcp", http.HandlerFunc(serveForbidden))
}

func serveRemovedStack(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(removedStackMsg)
}

func serveForbidden(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
}

func SetForwardedHeaders(req *http.Request) {
	if req.Header.Get("X-Forwarded-For") == "" {
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			req.Header.Set("X-Forwarded-For", host)
		}
	}
	if req.Header.Get("X-Forwarded-Proto") == "" {
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
	}
	if req.Header.Get("X-Forwarded-Host") == "" {
		req.Header.Set("X-Forwarded-Host", req.Host)
	}
}
