package main

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const grafanaSessionExpiryCookie = "grafana_session_expiry"

// grafanaSessionCookies are set by Grafana after auth.proxy login on GET /login
// (see Grafana docs + github.com/grafana/grafana/issues/48846).
var grafanaSessionCookies = []string{"grafana_session", "grafana_sess"}

// grafanaSessionMiddleware mints grafana_session via upstream GET /login when the
// browser has no valid session pair. Auth proxy alone sets userId in logs but does
// not create the cookie the Grafana 13 SPA needs for /api/user/auth-tokens/rotate.
type grafanaSessionMiddleware struct {
	upstream  string
	proxyUser string
	client    *http.Client
	next      http.Handler
}

func newGrafanaSessionMiddleware(upstreamURL, proxyUser string, next http.Handler) http.Handler {
	return &grafanaSessionMiddleware{
		upstream:  strings.TrimRight(upstreamURL, "/"),
		proxyUser: proxyUser,
		client:    &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		next:      next,
	}
}

func (m *grafanaSessionMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.needsMint(r) {
		cookies, err := m.mint(r.Context())
		if err != nil {
			slog.Warn("grafana session mint failed", "err", err)
		} else if len(cookies) > 0 {
			clearGrafanaSessionCookies(w)
			for _, c := range cookies {
				http.SetCookie(w, c)
			}
			target := r.URL.RequestURI()
			if target == "" {
				target = "/"
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}
	m.next.ServeHTTP(w, r)
}

func (m *grafanaSessionMiddleware) needsMint(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if grafanaStaticOrAPIPath(r.URL.Path) {
		return false
	}
	return !hasValidGrafanaSession(r)
}

func grafanaStaticOrAPIPath(path string) bool {
	switch {
	case path == "/login":
		return true
	case strings.HasPrefix(path, "/public/"):
		return true
	case strings.HasPrefix(path, "/avatar/"):
		return true
	case strings.HasPrefix(path, "/api/"):
		return true
	case strings.HasPrefix(path, "/apis/"):
		return true
	default:
		return false
	}
}

func hasValidGrafanaSession(r *http.Request) bool {
	sess, err := r.Cookie("grafana_session")
	if err != nil || sess.Value == "" {
		return false
	}
	exp, err := r.Cookie(grafanaSessionExpiryCookie)
	if err != nil || exp.Value == "" {
		return false
	}
	expUnix, err := strconv.ParseInt(exp.Value, 10, 64)
	if err != nil || time.Now().Unix() >= expUnix {
		return false
	}
	return true
}

func (m *grafanaSessionMiddleware) mint(ctx context.Context) ([]*http.Cookie, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.upstream+"/login", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(grafanaProxyUserHeader, m.proxyUser)
	req.Header.Set("X-Forwarded-Proto", "https")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, errGrafanaMintFailed
	}
	return resp.Cookies(), nil
}

var errGrafanaMintFailed = errGrafanaMint("grafana /login did not return session cookies")

type errGrafanaMint string

func (e errGrafanaMint) Error() string { return string(e) }

func clearGrafanaSessionCookies(w http.ResponseWriter) {
	for _, name := range append(grafanaSessionCookies, grafanaSessionExpiryCookie) {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name != grafanaSessionExpiryCookie,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}
