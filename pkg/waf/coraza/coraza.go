// Package coraza integrates OWASP Coraza WAF (ModSecurity-compatible) at the gateway edge.
package coraza

import (
	"fmt"
	"net/http"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	whttp "github.com/corazawaf/coraza/v3/http"
)

// Config tunes Coraza engine behavior.
type Config struct {
	Enabled          bool
	OWASPCRS         bool
	RequestBodyLimit int
	SkipPaths        []string
}

// DefaultConfig matches worker/proxy WAF defaults (10 MiB body limit).
func DefaultConfig() Config {
	return Config{
		Enabled:          true,
		OWASPCRS:         true,
		RequestBodyLimit: 10 << 20,
		SkipPaths: []string{
			"/storage/v1/",
			"/api/track",
			"/api/identify",
			"/api/script.js",
			"/api/site/tracking-config/",
			"/api/session-replay/",
		},
	}
}

// Middleware wraps inbound HTTP with Coraza inspection. Disabled config is a no-op.
type Middleware struct {
	waf       coraza.WAF
	skipPaths []string
}

// New builds Coraza middleware. Returns a pass-through when Enabled is false.
func New(cfg Config) (*Middleware, error) {
	if !cfg.Enabled {
		return &Middleware{}, nil
	}
	if cfg.RequestBodyLimit <= 0 {
		cfg.RequestBodyLimit = DefaultConfig().RequestBodyLimit
	}
	waf, err := buildWAF(cfg)
	if err != nil {
		return nil, err
	}
	return &Middleware{waf: waf, skipPaths: cfg.SkipPaths}, nil
}

func buildWAF(cfg Config) (coraza.WAF, error) {
	base := fmt.Sprintf(`
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyLimitAction ProcessPartial
SecAuditEngine Off
`, cfg.RequestBodyLimit)

	wafCfg := coraza.NewWAFConfig().WithDirectives(base)
	if cfg.OWASPCRS {
		wafCfg = wafCfg.
			WithRootFS(coreruleset.FS).
			WithDirectivesFromFile("@coraza.conf-recommended").
			WithDirectivesFromFile("@crs-setup.conf.example").
			WithDirectivesFromFile("@owasp_crs/*.conf")
	}
	return coraza.NewWAF(wafCfg)
}

// Wrap returns an http.Handler that runs Coraza before next.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	if m.waf == nil {
		return next
	}
	inner := whttp.WrapHandler(m.waf, next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, prefix := range m.skipPaths {
			if strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
		}
		inner.ServeHTTP(w, r)
	})
}

// AsGuard adapts to pkg/guard.Middleware for use in guard.Chain.
func (m *Middleware) AsGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return m.Wrap(next)
	}
}
