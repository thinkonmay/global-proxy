package main

import (
	"net/http"

	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
)

const wafConf = `
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 10485760
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyLimitAction ProcessPartial
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:(5|4)(0|1)[0-9])$"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLogFormat Native`

var (
	globalWAF      coraza.WAF
	allowedIPMap   map[string]struct{}
	allowedPathMap map[string]struct{}
)

func initWAF(allowedIPs []string, allowedPaths []string) error {
	allowedIPMap = make(map[string]struct{})
	for _, ip := range allowedIPs {
		allowedIPMap[ip] = struct{}{}
	}

	allowedPathMap = make(map[string]struct{})
	for _, path := range allowedPaths {
		allowedPathMap[path] = struct{}{}
	}

	conf := coraza.NewWAFConfig().WithDirectives(wafConf)
	waf, err := coraza.NewWAF(conf)
	if err != nil {
		return err
	}
	globalWAF = waf
	return nil
}

func isIPAllowed(ip string) bool {
	if len(allowedIPMap) == 0 {
		return true
	}
	_, ok := allowedIPMap[ip]
	return ok
}

func isPathAllowed(path string) bool {
	_, ok := allowedPathMap[path]
	return ok
}

func withWAF(next http.Handler) http.Handler {
	// Pre-wrap the handler with Coraza if globalWAF is initialized.
	// corazahttp.WrapHandler returns a handler that manages the lifecycle of transactions.
	var corazaHandler http.Handler
	if globalWAF != nil {
		corazaHandler = corazahttp.WrapHandler(globalWAF, next)
	} else {
		corazaHandler = next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		clientIP := getRemoteIP(req)

		// Check against whitelist before processing through Coraza WAF
		if !isPathAllowed(req.URL.Path) && !isIPAllowed(clientIP) {
			http.Error(w, "Forbidden: IP not authorized", http.StatusForbidden)
			return
		}

		corazaHandler.ServeHTTP(w, req)
	})
}
