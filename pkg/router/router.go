// Package router adds version-scoped route registration on top of the stdlib
// http.ServeMux. Callers declare paths relative to a shared prefix — typically
// an API version such as "/v1" — instead of repeating the prefix, the
// "METHOD path" concatenation, and the trailing-slash alias on every line.
//
// It carries no domain logic and no package state, so any layer (gateway
// handlers, payment providers) can depend on it without coupling.
package router

import (
	"net/http"
	"strings"
)

// Group registers routes under a shared path prefix. The zero value is not
// usable; construct one with New or V1.
type Group struct {
	mux    *http.ServeMux
	prefix string
}

// New returns a Group whose routes are registered under prefix. A trailing
// slash on prefix is ignored, so New(mux, "/v1") and New(mux, "/v1/") behave
// identically.
func New(mux *http.ServeMux, prefix string) *Group {
	return &Group{mux: mux, prefix: strings.TrimSuffix(prefix, "/")}
}

// V1 returns a Group scoped to the "/v1" API version.
func V1(mux *http.ServeMux) *Group { return New(mux, "/v1") }

// Handle registers fn for method and the group-prefixed path. For fixed paths
// it also registers a trailing-slash alias so "/x" and "/x/" both match. Paths
// ending in a multi-segment wildcard ("{name...}") or already ending in "/" are
// registered as-is, since a trailing-slash alias would be invalid or redundant.
func (g *Group) Handle(method, path string, fn http.HandlerFunc) {
	full := g.prefix + path
	g.mux.HandleFunc(method+" "+full, fn)
	if !strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "...}") {
		g.mux.HandleFunc(method+" "+full+"/", fn)
	}
}

// GETExact registers GET on the group-prefixed path without a trailing-slash alias.
// Use for fixed paths that sit beside wildcard siblings (e.g. /jobs/history next to
// /jobs/{jobId}/events) where a "/path/" prefix rule would overlap the wildcard.
func (g *Group) GETExact(path string, fn http.HandlerFunc) {
	g.mux.HandleFunc(http.MethodGet+" "+g.prefix+path, fn)
}

// GET registers a handler for GET requests on the group-prefixed path.
func (g *Group) GET(path string, fn http.HandlerFunc) { g.Handle(http.MethodGet, path, fn) }

// POST registers a handler for POST requests on the group-prefixed path.
func (g *Group) POST(path string, fn http.HandlerFunc) { g.Handle(http.MethodPost, path, fn) }

// PUT registers a handler for PUT requests on the group-prefixed path.
func (g *Group) PUT(path string, fn http.HandlerFunc) { g.Handle(http.MethodPut, path, fn) }

// DELETE registers a handler for DELETE requests on the group-prefixed path.
func (g *Group) DELETE(path string, fn http.HandlerFunc) { g.Handle(http.MethodDelete, path, fn) }
