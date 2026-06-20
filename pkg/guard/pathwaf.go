package guard

import (
	"net/http"
	"strings"
)

// PathWAFConfig restricts catalog read paths to allowed client IPs (globalproxy -waf-paths/-waf-ips).
type PathWAFConfig struct {
	AllowedIPs      []string
	PublicReadPaths []string
}

// PathWAF returns inbound middleware: when the request path matches a public read
// prefix and AllowedIPs is non-empty, the client IP must be in the allowlist.
func PathWAF(cfg PathWAFConfig) Middleware {
	allowed := IPSet(cfg.AllowedIPs...)
	prefixes := cfg.PublicReadPaths
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(prefixes) > 0 && len(cfg.AllowedIPs) > 0 &&
				isPublicReadMethod(r.Method) &&
				matchesPublicPath(r.URL.Path, prefixes) {
				if !allowed(r) {
					reject(w, http.StatusForbidden, "forbidden")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isPublicReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func matchesPublicPath(path string, prefixes []string) bool {
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if path == p || strings.HasPrefix(path, p+"/") || strings.HasPrefix(path, p+"?") {
			return true
		}
	}
	return false
}
