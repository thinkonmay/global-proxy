package pocketbase

import (
	"net/http"
	"testing"
)

func TestIssuerResolverResolve(t *testing.T) {
	r := NewIssuerResolver("https://haiphong.thinkmay.net", "https://host.docker.internal")

	tests := []struct {
		name   string
		client string
		want   string
	}{
		{
			name:   "matching public issuer rewrites to internal",
			client: "https://haiphong.thinkmay.net",
			want:   "https://host.docker.internal",
		},
		{
			name:   "trailing slash on issuer",
			client: "https://haiphong.thinkmay.net/",
			want:   "https://host.docker.internal",
		},
		{
			name:   "issuer with explicit port still matches hostname",
			client: "https://haiphong.thinkmay.net:443",
			want:   "https://host.docker.internal",
		},
		{
			name:   "bare hostname issuer",
			client: "haiphong.thinkmay.net",
			want:   "https://host.docker.internal",
		},
		{
			name:   "different cluster passes through",
			client: "https://saigon2.thinkmay.net",
			want:   "https://saigon2.thinkmay.net",
		},
		{
			name:   "empty issuer",
			client: "",
			want:   "",
		},
		{
			name:   "whitespace trimmed",
			client: "  https://haiphong.thinkmay.net  ",
			want:   "https://host.docker.internal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Resolve(tc.client); got != tc.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tc.client, got, tc.want)
			}
		})
	}
}

func TestIssuerResolverNoInternalURL(t *testing.T) {
	r := NewIssuerResolver("https://haiphong.thinkmay.net", "")

	tests := []struct {
		client string
		want   string
	}{
		{"https://haiphong.thinkmay.net", "https://haiphong.thinkmay.net"},
		{"https://saigon2.thinkmay.net", "https://saigon2.thinkmay.net"},
	}

	for _, tc := range tests {
		t.Run(tc.client, func(t *testing.T) {
			if got := r.Resolve(tc.client); got != tc.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tc.client, got, tc.want)
			}
		})
	}
}

func TestIssuerResolverNoPublicURL(t *testing.T) {
	r := NewIssuerResolver("", "https://host.docker.internal")
	got := r.Resolve("https://haiphong.thinkmay.net")
	if got != "https://haiphong.thinkmay.net" {
		t.Fatalf("Resolve without public URL should pass through, got %q", got)
	}
}

func TestIssuerResolverHostnameCaseInsensitive(t *testing.T) {
	r := NewIssuerResolver("https://Haiphong.Thinkmay.NET", "https://host.docker.internal")
	got := r.Resolve("https://HAIPHONG.thinkmay.net")
	if got != "https://host.docker.internal" {
		t.Fatalf("got %q", got)
	}
}

func TestHostFromBaseURL(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://haiphong.thinkmay.net:443", "haiphong.thinkmay.net"},
		{"https://haiphong.thinkmay.net", "haiphong.thinkmay.net"},
		{"haiphong.thinkmay.net", "haiphong.thinkmay.net"},
		{"http://127.0.0.1:8090", "127.0.0.1"},
		{"", ""},
		{"https://", ""},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			if got := hostFromBaseURL(tc.raw); got != tc.want {
				t.Fatalf("hostFromBaseURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestIssuerResolverUsesInternal(t *testing.T) {
	r := NewIssuerResolver("https://haiphong.thinkmay.net", "https://host.docker.internal")

	if !r.usesInternal("https://host.docker.internal") {
		t.Fatal("expected internal URL to be recognized")
	}
	if !r.usesInternal("https://host.docker.internal/") {
		t.Fatal("expected trailing slash to be trimmed")
	}
	if r.usesInternal("https://haiphong.thinkmay.net") {
		t.Fatal("public issuer should not count as internal")
	}
	if r.usesInternal("") {
		t.Fatal("empty should not be internal")
	}
}

func TestIssuerResolverSNITransport(t *testing.T) {
	r := NewIssuerResolver("https://haiphong.thinkmay.net", "https://host.docker.internal")
	tr, ok := r.sniTransport().(*http.Transport)
	if !ok {
		t.Fatalf("sniTransport type = %T", r.sniTransport())
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.ServerName != "haiphong.thinkmay.net" {
		t.Fatalf("ServerName = %q, want haiphong.thinkmay.net", tr.TLSClientConfig.ServerName)
	}
}

func TestIssuerResolverSNITransportEmptyPublic(t *testing.T) {
	r := NewIssuerResolver("", "https://host.docker.internal")
	if r.sniTransport() != nil {
		t.Fatal("expected nil sni transport without public URL")
	}
}

func TestIssuerResolverHTTPClientUsesSNITransportForInternal(t *testing.T) {
	r := NewIssuerResolver("https://haiphong.thinkmay.net", "https://host.docker.internal")
	fallback := http.DefaultTransport

	client := r.httpClient("https://host.docker.internal", fallback)
	if client.Transport == fallback {
		t.Fatal("expected SNI transport for internal resolved URL")
	}

	client = r.httpClient("https://saigon2.thinkmay.net", fallback)
	if client.Transport != fallback {
		t.Fatal("expected fallback transport for non-internal resolved URL")
	}
}
