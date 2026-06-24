package upstream

import (
	"net/http"
	"strings"
)

// gatewayAPIPrefixes are path prefixes handled by the gateway (not Next.js).
var gatewayAPIPrefixes = []string{
	"/rest/v1",
	"/graphql/v1",
	"/storage/v1",
	"/pg/",
	"/auth/v1/",
	"/realtime/v1/",
	"/functions/v1/",
	"/analytics/v1/",
	"/api/",
	"/v1/",
	"/sse",
	"/admin/",
}

// gatewayAPIExactPaths are non-prefix gateway routes.
var gatewayAPIExactPaths = []string{
	"/health",
	"/graphql/v1",
	"/sse",
}

func stripLocalePrefix(path string) string {
	if path == "" {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for _, loc := range []string{"/en/", "/vi/", "/id/"} {
		if strings.HasPrefix(path, loc) {
			return "/" + strings.TrimPrefix(path, loc)
		}
	}
	return path
}

func isGatewayAPIPath(path string) bool {
	path = stripLocalePrefix(path)
	if path == "" {
		return false
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for _, exact := range gatewayAPIExactPaths {
		if path == exact {
			return true
		}
	}
	for _, prefix := range gatewayAPIPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	if path == "/jobs" || strings.HasPrefix(path, "/jobs/") {
		return true
	}
	return false
}

// WrapWebsiteFallback sends non-API traffic to the Next.js PWA container (D17).
// When website is nil, only gateway routes are served.
func WrapWebsiteFallback(primary http.Handler, website http.Handler) http.Handler {
	if website == nil {
		return primary
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		normalized := stripLocalePrefix(r.URL.Path)
		if normalized != r.URL.Path {
			r2 := r.Clone(r.Context())
			r2.URL.Path = normalized
			r = r2
		}
		if isGatewayAPIPath(r.URL.Path) {
			primary.ServeHTTP(w, r)
			return
		}
		website.ServeHTTP(w, r)
	})
}
