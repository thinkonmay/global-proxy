package upstream

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestRewriteLocationToPublicOrigin(t *testing.T) {
	tests := []struct {
		name         string
		location     string
		upstreamHost string
		clientHost   string
		want         string
	}{
		{
			name:         "litellm ui redirect",
			location:     "http://litellm:4000/ui/",
			upstreamHost: "litellm:4000",
			clientHost:   "analytics.haiphong.thinkmay.net:4433",
			want:         "https://analytics.haiphong.thinkmay.net:4433/ui/",
		},
		{
			name:         "https upstream redirect",
			location:     "https://litellm:4000/ui/login",
			upstreamHost: "litellm:4000",
			clientHost:   "analytics.haiphong.thinkmay.net:4433",
			want:         "https://analytics.haiphong.thinkmay.net:4433/ui/login",
		},
		{
			name:         "external location unchanged",
			location:     "https://example.com/path",
			upstreamHost: "litellm:4000",
			clientHost:   "analytics.haiphong.thinkmay.net:4433",
			want:         "https://example.com/path",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ui", nil)
			req.Host = tc.clientHost
			req.TLS = &tls.ConnectionState{}
			rec := httptest.NewRecorder()
			rec.Header().Set("Location", tc.location)
			resp := rec.Result()
			resp.Request = req

			RewriteLocationToPublicOrigin(resp, tc.upstreamHost)

			if got := resp.Header.Get("Location"); got != tc.want {
				t.Fatalf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLocationRewriteModifier(t *testing.T) {
	req := httptest.NewRequest("GET", "/ui", nil)
	req.Host = "litellm.thinkmay.net:4433"
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	rec.Header().Set("Location", "http://litellm:4000/ui/")
	resp := rec.Result()
	resp.Request = req

	mod := LocationRewriteModifier("http://litellm:4000")
	if err := mod(resp); err != nil {
		t.Fatal(err)
	}
	want := "https://litellm.thinkmay.net:4433/ui/"
	if got := resp.Header.Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}
