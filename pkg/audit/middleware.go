package audit

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/thinkonmay/global-proxy/api/pkg/guard"
)

const requestIDHeader = "X-Request-ID"

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware attaches request_id, records http.access audit events, and propagates
// correlation ids on the request context (OC2).
func Middleware(rec *Recorder) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rec == nil {
				next.ServeHTTP(w, r)
				return
			}

			id := strings.TrimSpace(r.Header.Get(requestIDHeader))
			if id == "" {
				id = uuid.NewString()
			}
			ctx := WithRequestID(r.Context(), id)
			r = r.WithContext(ctx)
			w.Header().Set(requestIDHeader, id)

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			action := Action(ctx)
			if action == "" {
				action = "http.access"
			}
			ev := newEvent(action, "gateway")
			ev.RequestID = id
			ev.Route = r.URL.Path
			ev.Method = r.Method
			ev.Status = sw.status
			ev.RemoteIP = guard.ClientIP(r)
			ev.Host = r.Host
			ev.UserAgent = r.Header.Get("User-Agent")
			ev.UserEmail = UserEmail(ctx)
			rec.Record(ev)
		})
	}
}

// RecordAuthProxy logs a structured auth proxy access (D28).
func RecordAuthProxy(rec *Recorder, r *http.Request) {
	if rec == nil || r == nil {
		return
	}
	ev := newEvent("auth.proxy", "auth_proxy")
	ev.RequestID = RequestID(r.Context())
	ev.Route = r.URL.Path
	ev.Method = r.Method
	ev.RemoteIP = guard.ClientIP(r)
	ev.Host = r.Host
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Detail = r.Header.Get("X-Forwarded-For")
	rec.Record(ev)
}

// RecordAdmin logs B12 admin gate events.
func RecordAdmin(rec *Recorder, r *http.Request, action, email, detail string) {
	if rec == nil {
		return
	}
	ev := newEvent(action, "admin")
	if r != nil {
		ev.RequestID = RequestID(r.Context())
		ev.Route = r.URL.Path
		ev.Method = r.Method
		ev.RemoteIP = guard.ClientIP(r)
		ev.Host = r.Host
	}
	ev.UserEmail = email
	ev.Detail = detail
	rec.Record(ev)
}
