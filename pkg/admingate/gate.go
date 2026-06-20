package admingate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/guard"
	"github.com/thinkonmay/global-proxy/api/pkg/supabase/auth"
)

// Config for B12 admin gate (IP + email + Redis OTP SSO + basic-auth).
type Config struct {
	Enabled         bool
	AllowedIPs      []string
	AllowedEmails   []string
	CookieDomain    string
	SessionTTLHours int
	OTPTTLMinutes   int
	SigningSecret   string
	BasicAuthUser   string
	BasicAuthPass   string
}

// Gate enforces admin access controls and serves OTP login handlers.
type Gate struct {
	cfg   Config
	otp   OTPStore
	mail  Mailer
	secret []byte
	ipMatch guard.Match
	emails  map[string]struct{}
}

// NewGate builds an admin gate. allowedEmails map is normalized to lowercase.
func NewGate(cfg Config, otp OTPStore, mail Mailer) (*Gate, error) {
	if cfg.SigningSecret == "" {
		return nil, errSigningSecret
	}
	emails := make(map[string]struct{}, len(cfg.AllowedEmails))
	for _, e := range cfg.AllowedEmails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			emails[e] = struct{}{}
		}
	}
	return &Gate{
		cfg:     cfg,
		otp:     otp,
		mail:    mail,
		secret:  []byte(cfg.SigningSecret),
		ipMatch: guard.IPSet(cfg.AllowedIPs...),
		emails:  emails,
	}, nil
}

var errSigningSecret = &gateError{msg: "admin signing secret required"}

type gateError struct{ msg string }

func (e *gateError) Error() string { return e.msg }

func (g *Gate) emailAllowed(email string) bool {
	if len(g.emails) == 0 {
		return true
	}
	_, ok := g.emails[strings.ToLower(strings.TrimSpace(email))]
	return ok
}

func (g *Gate) ipAllowed(r *http.Request) bool {
	if len(g.cfg.AllowedIPs) == 0 {
		return true
	}
	return g.ipMatch(r)
}

func (g *Gate) sessionFromRequest(r *http.Request) (Session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return Session{}, false
	}
	sess, err := parseSession(c.Value, g.secret)
	if err != nil {
		return Session{}, false
	}
	if !g.emailAllowed(sess.Email) {
		return Session{}, false
	}
	return sess, true
}

func exemptPath(path string) bool {
	switch path {
	case "/admin/login", "/admin/otp/request", "/admin/otp/verify":
		return true
	}
	return strings.HasPrefix(path, "/admin/login")
}

// Protect wraps an admin upstream handler (OTP SSO, then basic-auth is applied separately).
func (g *Gate) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if !g.ipAllowed(r) {
			writeJSON(w, http.StatusForbidden, `{"message":"forbidden"}`)
			return
		}
		if _, ok := g.sessionFromRequest(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		nextURL := url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, "/admin/login?next="+nextURL, http.StatusFound)
	})
}

// WithBasicAuth adds Kong-style basic-auth as the last defense before upstream.
func (g *Gate) WithBasicAuth(next http.Handler) http.Handler {
	return auth.BasicAuth(g.cfg.BasicAuthUser, g.cfg.BasicAuthPass)(next)
}

// RegisterRoutes mounts SSO OTP login handlers on mux.
func (g *Gate) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/login", g.serveLogin)
	mux.HandleFunc("POST /admin/otp/request", g.handleOTPRequest)
	mux.HandleFunc("POST /admin/otp/verify", g.handleOTPVerify)
}

func (g *Gate) serveLogin(w http.ResponseWriter, r *http.Request) {
	if !g.ipAllowed(r) {
		writeJSON(w, http.StatusForbidden, `{"message":"forbidden"}`)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, loginHTML(next))
}

func (g *Gate) handleOTPRequest(w http.ResponseWriter, r *http.Request) {
	if !g.ipAllowed(r) {
		writeJSON(w, http.StatusForbidden, `{"message":"forbidden"}`)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, `{"message":"email required"}`)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !g.emailAllowed(email) {
		writeJSON(w, http.StatusForbidden, `{"message":"email not allowed"}`)
		return
	}
	code, err := generateOTP()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, `{"message":"otp generation failed"}`)
		return
	}
	ttl := time.Duration(g.cfg.OTPTTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if err := g.otp.Save(r.Context(), email, code, ttl); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, `{"message":"otp store unavailable"}`)
		return
	}
	if err := g.mail.SendOTP(r.Context(), email, code); err != nil {
		writeJSON(w, http.StatusBadGateway, `{"message":"failed to send otp"}`)
		return
	}
	writeJSON(w, http.StatusOK, `{"message":"otp sent"}`)
}

func (g *Gate) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	if !g.ipAllowed(r) {
		writeJSON(w, http.StatusForbidden, `{"message":"forbidden"}`)
		return
	}
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
		Next  string `json:"next"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, `{"message":"email and code required"}`)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !g.emailAllowed(email) {
		writeJSON(w, http.StatusForbidden, `{"message":"email not allowed"}`)
		return
	}
	ok, err := g.otp.Verify(r.Context(), email, strings.TrimSpace(req.Code))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, `{"message":"otp store unavailable"}`)
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, `{"message":"invalid or expired code"}`)
		return
	}
	ttl := sessionTTL(g.cfg.SessionTTLHours)
	exp := time.Now().Add(ttl)
	token, _, err := signSession(email, exp, g.secret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, `{"message":"session error"}`)
		return
	}
	domain := g.cfg.CookieDomain
	if domain == "" {
		domain = ".thinkmay.net"
	}
	w.Header().Add("Set-Cookie", formatCookie(token, domain, ttl))
	writeJSON(w, http.StatusOK, `{"message":"ok","next":`+jsonString(req.Next)+`}`)
}

func jsonString(s string) string {
	if s == "" {
		return `"/"`
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func writeJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

func loginHTML(next string) string {
	return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Thinkmay Admin</title></head>
<body>
<h1>Admin login</h1>
<p>Enter your team email. We will send a one-time code valid across all admin dashboards.</p>
<label>Email <input id="email" type="email" autocomplete="username"></label>
<button id="send">Send code</button>
<label>Code <input id="code" type="text" inputmode="numeric" autocomplete="one-time-code"></label>
<button id="verify">Verify</button>
<pre id="msg"></pre>
<script>
const next = ` + jsonString(next) + `;
const msg = document.getElementById('msg');
document.getElementById('send').onclick = async () => {
  const email = document.getElementById('email').value;
  const r = await fetch('/admin/otp/request', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email})});
  msg.textContent = await r.text();
};
document.getElementById('verify').onclick = async () => {
  const email = document.getElementById('email').value;
  const code = document.getElementById('code').value;
  const r = await fetch('/admin/otp/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email, code, next})});
  const body = await r.json();
  msg.textContent = JSON.stringify(body);
  if (r.ok && body.next) location.href = body.next;
};
</script>
</body></html>`
}

// ProtectInternal applies the same SSO gate to internal API paths on the public host.
func (g *Gate) ProtectInternal(next http.Handler) http.Handler {
	return g.Protect(next)
}

// SessionFromRequest returns the validated SSO session when present.
func (g *Gate) SessionFromRequest(r *http.Request) (Session, bool) {
	return g.sessionFromRequest(r)
}

// SaveOTP stores an OTP for tests and integration bootstrap.
func (g *Gate) SaveOTP(ctx context.Context, email, code string, ttl time.Duration) error {
	return g.otp.Save(ctx, email, code, ttl)
}

// Close releases Redis resources when applicable.
func (g *Gate) Close() error {
	if c, ok := g.otp.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

var _ OTPStore = (*RedisOTPStore)(nil)
