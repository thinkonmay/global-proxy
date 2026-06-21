package pocketbase

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
)

// IssuerResolver maps client-supplied issuer URLs (public node hostname) to a
// base URL the gateway container can reach for auth-refresh. On dev hosts where
// PocketBase binds host :443 and the gateway runs in Docker on :4433, hairpin
// NAT often breaks outbound calls to the public issuer URL; InternalURL should
// point at the host (e.g. https://host.docker.internal).
type IssuerResolver struct {
	publicURL   string
	internalURL string
}

func NewIssuerResolver(publicURL, internalURL string) IssuerResolver {
	return IssuerResolver{
		publicURL:   strings.TrimRight(strings.TrimSpace(publicURL), "/"),
		internalURL: strings.TrimRight(strings.TrimSpace(internalURL), "/"),
	}
}

// Resolve returns the outbound base URL for auth-refresh. When internalURL is
// configured and clientIssuer matches publicURL by hostname, internalURL is used.
func (r IssuerResolver) Resolve(clientIssuer string) string {
	clientIssuer = strings.TrimRight(strings.TrimSpace(clientIssuer), "/")
	if clientIssuer == "" {
		return clientIssuer
	}
	if r.internalURL == "" {
		return clientIssuer
	}
	pubHost := hostFromBaseURL(r.publicURL)
	clientHost := hostFromBaseURL(clientIssuer)
	if pubHost == "" || clientHost == "" {
		return clientIssuer
	}
	if strings.EqualFold(pubHost, clientHost) {
		return r.internalURL
	}
	return clientIssuer
}

func hostFromBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	host, _, _ := strings.Cut(u.Host, ":")
	if host == "" {
		return strings.ToLower(strings.TrimSpace(u.Host))
	}
	return strings.ToLower(host)
}

func (r IssuerResolver) usesInternal(resolved string) bool {
	resolved = strings.TrimRight(strings.TrimSpace(resolved), "/")
	return r.internalURL != "" && resolved == r.internalURL
}

// httpClient returns an HTTP client for auth-refresh. When the resolved base is
// the internal URL, TLS ServerName is set to the public PB hostname so host certs validate.
func (r IssuerResolver) httpClient(resolved string, rt http.RoundTripper) *http.Client {
	transport := rt
	if r.usesInternal(resolved) {
		if sni := r.sniTransport(); sni != nil {
			transport = sni
		}
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{Transport: transport}
}

func (r IssuerResolver) sniTransport() http.RoundTripper {
	pubHost := hostFromBaseURL(r.publicURL)
	if pubHost == "" {
		return nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{ServerName: pubHost}
	return tr
}
