package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	certdoms = []string{"play.2.thinkmay.net"}
	sport    = 446
)

type analytic struct {
	timestamp time.Time
	data      []byte
}
type nodeCache struct {
	typeMap map[string]*analytic
	mut     *sync.Mutex
}

type analyticCache struct {
	nodeMap map[string]*nodeCache
	mut     *sync.Mutex
}

func StartPocketbase() {
	// Reverse proxies
	apiProxy := newReverseProxy("http://localhost:3001")
	rootProxy := newReverseProxy("http://localhost:3002")

	cache := analyticCache{
		nodeMap: map[string]*nodeCache{},
		mut:     &sync.Mutex{},
	}
	// HTTPS mux
	mux := http.NewServeMux()
	mux.Handle("/api/", apiProxy)
	mux.Handle("/", rootProxy)

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("./pb_data/.autocert_cache"),
		HostPolicy: autocert.HostWhitelist(certdoms...),
	}
	// base request context used for cancelling long running requests
	// like the SSE connections
	baseCtx, cancelBaseCtx := context.WithCancel(context.Background())
	defer cancelBaseCtx()

	publicMux := http.NewServeMux()
	publicMux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		node := r.Header.Get("node")
		t := r.Header.Get("type")
		if credential := r.Header.Get("Authorization"); credential != "abc" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		cache.mut.Lock()
		defer cache.mut.Unlock()
		if nodeData, found := cache.nodeMap[node]; found {
			nodeData.mut.Lock()
			nodeData.typeMap[t] = &analytic{timestamp: time.Now(), data: data}
			nodeData.mut.Unlock()
		} else {
			cache.nodeMap[node] = &nodeCache{
				mut: &sync.Mutex{},
				typeMap: map[string]*analytic{
					t: {timestamp: time.Now(), data: data},
				},
			}
		}
	})

	privateMux := http.NewServeMux()
	privateMux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		if credential := r.Header.Get("Authorization"); credential != "abc" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		type res struct {
			Type     string `json:"type"`
			NodeName string `json:"nodeName"`
			Data     string `json:"data"`
		}
		result := []res{}

		cache.mut.Lock()
		for nname, node := range cache.nodeMap {
			node.mut.Lock()
			for typ, val := range node.typeMap {
				if time.Since(val.timestamp) <= 5*time.Minute {
					result = append(result, res{
						Type:     typ,
						Data:     string(val.data),
						NodeName: nname,
					})
				}
			}
			node.mut.Unlock()
		}
		cache.mut.Unlock()

		dataJSON, _ := json.Marshal(result)
		w.Header().Set("Content-Type", "application/json")
		w.Write(dataJSON)
	})

	server := &http.Server{
		BaseContext: func(l net.Listener) context.Context { return baseCtx },
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certManager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto},
		},

		ReadTimeout:       10 * time.Minute,
		ReadHeaderTimeout: 30 * time.Second,
		Addr:              fmt.Sprintf(":%d", sport),
		Handler:           mux,
	}

	privateServer := &http.Server{
		Addr:    ":3050",
		Handler: privateMux,
	}

	go func() {
		if err := privateServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("private server error: %v", err)
		}
	}()

	panic(server.ListenAndServeTLS("", ""))
}

func main() {
	go StartPocketbase()

	sigchan := make(chan os.Signal, 16)
	signal.Notify(sigchan, syscall.SIGTERM, os.Interrupt)
	sig := <-sigchan

	fmt.Printf("receive signal %s from os\n", sig.String())
}

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
