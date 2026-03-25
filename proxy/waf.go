package main

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
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

var globalWAF coraza.WAF

func initWAF() error {
	conf := coraza.NewWAFConfig().
		WithDirectives(wafConf)
	waf, err := coraza.NewWAF(conf)
	if err != nil {
		return err
	}
	globalWAF = waf
	return nil
}

func withWAF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if globalWAF == nil {
			next.ServeHTTP(w, req)
			return
		}

		tx := globalWAF.NewTransaction()
		defer tx.ProcessLogging()
		defer tx.Close()

		if tx.IsRuleEngineOff() {
			next.ServeHTTP(w, req)
			return
		}

		it, err := processRequest(tx, req)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if it != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, req)
	})
}

func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	var (
		client string
		cport  int
	)
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx != -1 {
		client = req.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
	}

	var in *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	// Host will always be removed from req.Headers() and promoted to the
	// Request.Host field, so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(req.Host)
	}

	// Transfer-Encoding header is removed by go/http
	// We manually add it to make rules relying on it work (E.g. CRS rule 920171)
	if len(req.TransferEncoding) > 0 {
		tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}

	if tx.IsRequestBodyAccessible() {
		// We only do body buffering if the transaction requires request
		// body inspection, otherwise we just let the request follow its
		// regular flow.
		if req.Body != nil && req.Body != http.NoBody {
			it, _, err := tx.ReadRequestBodyFrom(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to append request body: %v", err)
			}

			if it != nil {
				return it, nil
			}

			rbr, err := tx.RequestBodyReader()
			if err != nil {
				return nil, fmt.Errorf("failed to get the request body: %v", err)
			}

			// Adds all remaining bytes beyond the coraza limit to its buffer
			// It happens when the partial body has been processed and it did not trigger an interruption
			bodyReader := io.MultiReader(rbr, req.Body)
			// req.Body is transparently reinizialied with a new io.ReadCloser.
			// The http handler will be able to read it.
			req.Body = io.NopCloser(bodyReader)
		}
	}

	return tx.ProcessRequestBody()
}
