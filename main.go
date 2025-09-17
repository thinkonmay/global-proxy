package main

import (
	"context"
	"crypto/tls"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	certdoms = []string{}
	sport    = 0
	rport    = 0
	qport    = 0
	cache    = analyticCache{
		nodeMap: make(map[string]*nodeCache),
		mut:     &sync.Mutex{},
	}
	credentialAnalytics = ""
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
	mux := http.NewServeMux()
	if len(certdoms) > 0 {
		apiProxy := newReverseProxy("http://localhost:3001")
		rootProxy := newReverseProxy("http://localhost:3002")
		mux.Handle("/api/", apiProxy)
		mux.Handle("/", rootProxy)
		// Reverse proxies
		rportAnalytics := newReverseProxy("http://localhost:3050")
		// // HTTPS mux
		mux.Handle("/report", rportAnalytics)

		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache("./pb_data/.autocert_cache"),
			HostPolicy: autocert.HostWhitelist(certdoms...),
		}
		// base request context used for cancelling long running requests
		// like the SSE connections
		baseCtx, cancelBaseCtx := context.WithCancel(context.Background())
		defer cancelBaseCtx()

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
		panic(server.ListenAndServe())
	}
}

func main() {
	args := os.Args
	var err error
	if sport, err = strconv.Atoi(args[1]); err != nil {
		return
	} else if qport, err = strconv.Atoi(args[2]); err != nil {
		return
	} else if rport, err = strconv.Atoi(args[3]); err != nil {
		return
	} else if credentialAnalytics = args[4]; len(credentialAnalytics) == 0 {
		return
	} else {
		certdoms = args[5:]
		SafeThread(StartPocketbase)
		SafeThread(StartQueryAnalytics)
		SafeThread(StartReportAnalytics)

		sigchan := make(chan os.Signal, 16)
		signal.Notify(sigchan, syscall.SIGTERM, os.Interrupt)
		sig := <-sigchan

		fmt.Printf("receive signal %s from os\n", sig.String())
	}
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

func StartReportAnalytics() {
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if credential := r.Header.Get("Authorization"); credential != credentialAnalytics {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if typ := r.Header.Get("type"); len(typ) == 0 {
			return
		} else if node := r.Header.Get("node"); len(node) == 0 {
			return
		} else if data, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		} else {
			cache.mut.Lock()
			defer cache.mut.Unlock()
			if nodeData, found := cache.nodeMap[node]; found {
				nodeData.mut.Lock()
				nodeData.typeMap[typ] = &analytic{timestamp: time.Now(), data: data}
				nodeData.mut.Unlock()
			} else {
				cache.nodeMap[node] = &nodeCache{
					mut: &sync.Mutex{},
					typeMap: map[string]*analytic{
						typ: {timestamp: time.Now(), data: data},
					},
				}
			}
		}
	})
	publicSever := &http.Server{
		Addr:    fmt.Sprintf(":%d", rport),
		Handler: publicMux,
	}
	panic(publicSever.ListenAndServe())
}

func StartQueryAnalytics() {
	privateMux := http.NewServeMux()
	privateMux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		if credential := r.Header.Get("Authorization"); credential != credentialAnalytics {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if destnode := r.Header.Get("node"); len(destnode) == 0 {
			return
		} else if desttyp := r.Header.Get("type"); len(desttyp) == 0 {
		} else {
			cache.mut.Lock()
			defer cache.mut.Unlock()
			if nodeData, found := cache.nodeMap[destnode]; !found {
				return
			} else {
				nodeData.mut.Lock()
				defer nodeData.mut.Unlock()
				w.Write(nodeData.typeMap[desttyp].data)
				return
			}
		}
	})

	privateServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", qport),
		Handler: privateMux,
	}
	panic(privateServer.ListenAndServe())
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
