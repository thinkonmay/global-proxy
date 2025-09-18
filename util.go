package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime/debug"
	"strings"
	"time"
)

func SafeLoop(sleep_period time.Duration, fun func() bool) {
	loop := func() bool {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("panic happened in safe loop %s\n", string(debug.Stack()))
			}
		}()

		return fun()
	}

	go func() {
		for {
			if !loop() {
				break
			}
			if sleep_period > 0 {
				time.Sleep(sleep_period)
			}
		}
	}()
}

// Extract client IP
func getRemoteIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

// Append to X-Forwarded-For
func appendXForwardedFor(req *http.Request) string {
	ip := getRemoteIP(req)
	if prior, ok := req.Header["X-Forwarded-For"]; ok {
		return strings.Join(prior, ", ") + ", " + ip
	}
	return ip
}

// Determine scheme
func getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// newReverseProxy returns a configured reverse proxy to target
func newReverseProxy(target string) *httputil.ReverseProxy {
	u, err := url.Parse(target)
	if err != nil {
		log.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Set headers like Nginx does
		req.Header.Set("Host", req.Host)
		req.Header.Set("X-Real-IP", getRemoteIP(req))
		req.Header.Set("X-Forwarded-For", appendXForwardedFor(req))
		req.Header.Set("X-Forwarded-Proto", getScheme(req))
	}

	return proxy
}

func SafeThread(fun func()) {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("panic happened in safe thread %v %s\n", err, string(debug.Stack()))
			}
		}()
		fun()
	}()
}

// StringSlice implements flag.Value for a slice of strings.
type StringSlice []string

// String returns a string representation of the slice.
func (s *StringSlice) String() string {
	return strings.Join(*s, ",")
}

// Set appends the value to the slice.
func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}
