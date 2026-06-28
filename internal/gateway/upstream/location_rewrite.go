package upstream

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ResponseModifier runs on upstream responses before they are sent to the client.
type ResponseModifier func(*http.Response) error

// LocationRewriteModifier rewrites Location headers that point at the internal
// upstream host (e.g. litellm:4000) to the client-facing gateway origin.
func LocationRewriteModifier(upstreamRawURL string) ResponseModifier {
	upstreamHost := ""
	if u, err := url.Parse(upstreamRawURL); err == nil {
		upstreamHost = u.Host
	}
	return func(resp *http.Response) error {
		RewriteLocationToPublicOrigin(resp, upstreamHost)
		return nil
	}
}

// RewriteLocationToPublicOrigin replaces upstream-only redirect targets with the
// browser-visible scheme and Host from the original client request.
func RewriteLocationToPublicOrigin(resp *http.Response, upstreamHost string) {
	if resp == nil || resp.Request == nil || upstreamHost == "" {
		return
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil || !locationFromUpstream(u, upstreamHost) {
		return
	}
	req := resp.Request
	scheme := "https"
	if req.TLS == nil {
		if v := strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")); v != "" {
			scheme = v
		} else {
			scheme = "http"
		}
	}
	publicHost := strings.TrimSpace(req.Header.Get("X-Forwarded-Host"))
	if publicHost == "" {
		publicHost = req.Host
	}
	if publicHost == "" {
		return
	}
	u.Scheme = scheme
	u.Host = publicHost
	resp.Header.Set("Location", u.String())
}

func locationFromUpstream(u *url.URL, upstreamHost string) bool {
	if u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, upstreamHost) {
		return true
	}
	upstreamName := upstreamHost
	if h, _, err := net.SplitHostPort(upstreamHost); err == nil {
		upstreamName = h
	}
	return strings.EqualFold(u.Hostname(), upstreamName)
}

// SetAdminForwardedHeaders sets proxy headers for admin dashboard upstreams
// (Studio, LiteLLM, Grafana). Call after TLS termination at the gateway.
func SetAdminForwardedHeaders(req *http.Request) {
	req.Header.Set("X-Forwarded-Proto", "https")
	SetForwardedHeaders(req)
	if _, port, err := net.SplitHostPort(req.Host); err == nil && port != "" && port != "443" && port != "80" {
		req.Header.Set("X-Forwarded-Port", port)
	}
}
