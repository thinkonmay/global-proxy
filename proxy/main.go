package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Config struct {
	Domains     []string    `yaml:"domains"`
	Ports       PortsConfig `yaml:"ports"`
	AnalyticCred string     `yaml:"analytic_cred"`
	WAF         WAFConfig   `yaml:"waf"`
}

type PortsConfig struct {
	Sport int `yaml:"sport"`
	Qport int `yaml:"qport"`
	Rport int `yaml:"rport"`
	Gport int `yaml:"gport"`
	Feport int `yaml:"feport"`
}

type WAFConfig struct {
	AllowedIPs   []string `yaml:"allowed_ips"`
	AllowedPaths []string `yaml:"allowed_paths"`
}

var (
	certdoms                          = StringSlice{}
	sport, qport, rport, gport, fport = 0, 0, 0, 0, 0
	analyticCred                      = ""

	publicMux   = http.NewServeMux()
	privateMux  = http.NewServeMux()
	certManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("./pb_data/.autocert_cache"),
	}
	cache = analyticCache{
		nodeMap: make(map[string]*nodeCache),
		mut:     &sync.Mutex{},
	}

	cfg = Config{}
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

func init() {
	data, err := os.ReadFile("/etc/gateway/config.yaml")
	if err != nil {
		fmt.Printf("failed to read config file: %v\n", err)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("failed to parse config file: %v\n", err)
		os.Exit(1)
	}

	for _, d := range cfg.Domains {
		certdoms = append(certdoms, d)
	}
	certManager.HostPolicy = autocert.HostWhitelist(certdoms...)

	sport = cfg.Ports.Sport
	qport = cfg.Ports.Qport
	rport = cfg.Ports.Rport
	gport = cfg.Ports.Gport
	fport = cfg.Ports.Feport
	analyticCred = cfg.AnalyticCred

	if analyticCred != "" {
		PrepareReportHandler()
	}
}

func main() {
	if err := initWAF(cfg.WAF.AllowedIPs, cfg.WAF.AllowedPaths); err != nil {
		fmt.Printf("failed to initialize WAF: %v\n", err)
	}

	stop1 := StartGlobalProxy()
	stop2 := StartQueryAnalytics()
	stop3 := StartRybbit()
	stop4 := StartG4Global()
	stop5 := StartFeGlobal()

	sigchan := make(chan os.Signal, 16)
	signal.Notify(sigchan, syscall.SIGTERM, os.Interrupt)

	select {
	case err := <-stop1:
		fmt.Printf("receive error %v from supabase proxy\n", err)
	case err := <-stop2:
		fmt.Printf("receive error %v from query analytics\n", err)
	case err := <-stop3:
		fmt.Printf("receive error %v from rybbit\n", err)
	case err := <-stop4:
		fmt.Printf("receive error %v from g4global\n", err)
	case err := <-stop5:
		fmt.Printf("receive error %v from feglobal\n", err)
	case sig := <-sigchan:
		fmt.Printf("receive signal %s from os\n", sig.String())
	}
}

func StartGlobalProxy() <-chan error {
	if len(certdoms) == 0 {
		fmt.Println("no certdoms provided, don't start global proxy")
		return make(<-chan error)
	} else if sport == 0 {
		fmt.Println("no sport provided, don't start global proxy")
		return make(<-chan error)
	}

	publicMux.Handle("/", withWAF(withCORS(newReverseProxy("http://kong:8000"))))

	// base request context used for cancelling long running requests
	// like the SSE connections
	baseCtx, cancelBaseCtx := context.WithCancel(context.Background())

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
		Handler:           publicMux,
	}
	res := make(chan error)
	SafeThread(func() {
		fmt.Printf("global proxy listening on port %d\n", sport)
		defer cancelBaseCtx()
		res <- server.ListenAndServeTLS("", "")
	})
	return res
}

func PrepareReportHandler() {
	publicMux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if credential := r.Header.Get("Authorization"); credential != analyticCred {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		} else if typ := r.Header.Get("type"); len(typ) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		} else if node := r.Header.Get("node"); len(node) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		} else if data, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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
}

func StartQueryAnalytics() <-chan error {
	if qport == 0 {
		fmt.Println("no qport provided, don't start query API")
		return make(<-chan error)
	}

	privateMux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		if destnode := r.Header.Get("node"); len(destnode) == 0 {
			w.WriteHeader(404)
		} else if desttyp := r.Header.Get("type"); len(desttyp) == 0 {
			w.WriteHeader(404)
		} else {
			cache.mut.Lock()
			defer cache.mut.Unlock()
			if nodeData, found := cache.nodeMap[destnode]; found {
				nodeData.mut.Lock()
				defer nodeData.mut.Unlock()
				if time.Since(nodeData.typeMap[desttyp].timestamp) < 1*time.Minute {
					w.WriteHeader(200)
					w.Write(nodeData.typeMap[desttyp].data)
				}
			}
		}
	})

	privateMux.HandleFunc("/all", func(w http.ResponseWriter, r *http.Request) {
		cache.mut.Lock()
		defer cache.mut.Unlock()

		keys := make([]string, 0, len(cache.nodeMap))
		for k := range cache.nodeMap {
			keys = append(keys, k)
		}
		res, err := json.Marshal(keys)

		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte(err.Error()))
		} else {
			w.WriteHeader(200)
			w.Write(res)
		}
	})

	privateServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", qport),
		Handler: privateMux,
	}

	res := make(chan error)
	SafeThread(func() {
		fmt.Printf("query analytics listening on port %d\n", qport)
		res <- privateServer.ListenAndServe()
	})
	return res
}

func StartRybbit() <-chan error {
	if len(certdoms) == 0 {
		fmt.Println("no certdoms provided, don't rybbit proxy")
		return make(<-chan error)
	} else if rport == 0 {
		fmt.Println("no rport provided, don't start rybbit proxy")
		return make(<-chan error)
	}

	publicMux.Handle("/api/", withCORS(newReverseProxy("http://backend:3001")))
	publicMux.Handle("/", withCORS(newReverseProxy("http://client:3002")))

	// base request context used for cancelling long running requests
	// like the SSE connections
	baseCtx, cancelBaseCtx := context.WithCancel(context.Background())

	server := &http.Server{
		BaseContext: func(l net.Listener) context.Context { return baseCtx },
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certManager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto},
		},

		ReadTimeout:       10 * time.Minute,
		ReadHeaderTimeout: 30 * time.Second,
		Addr:              fmt.Sprintf(":%d", rport),
		Handler:           publicMux,
	}

	res := make(chan error)
	SafeThread(func() {
		fmt.Printf("rybbit listening on port %d\n", rport)
		res <- server.ListenAndServeTLS("", "")
		cancelBaseCtx()
	})

	return res
}

func StartG4Global() <-chan error {
	if len(certdoms) == 0 {
		fmt.Println("no certdoms provided, don't g4global proxy")
		return make(<-chan error)
	} else if gport == 0 {
		fmt.Println("no gport provided, don't start g4global proxy")
		return make(<-chan error)
	}

	publicMux.Handle("/", withCORS(newReverseProxy("http://kong:8000")))

	// base request context used for cancelling long running requests
	// like the SSE connections
	baseCtx, cancelBaseCtx := context.WithCancel(context.Background())

	server := &http.Server{
		BaseContext: func(l net.Listener) context.Context { return baseCtx },
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certManager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto},
		},

		ReadTimeout:       10 * time.Minute,
		ReadHeaderTimeout: 30 * time.Second,
		Addr:              fmt.Sprintf(":%d", gport),
		Handler:           publicMux,
	}

	res := make(chan error)
	SafeThread(func() {
		fmt.Printf("g4global listening on port %d\n", gport)
		res <- server.ListenAndServeTLS("", "")
		cancelBaseCtx()
	})

	return res
}
func StartFeGlobal() <-chan error {
	if len(certdoms) == 0 {
                fmt.Println("no certdoms provided, don't feglobal proxy")
                return make(<-chan error)
        } else if fport == 0 {
                fmt.Println("no feport provided, don't start feglobal proxy")
                return make(<-chan error)
        }

        publicMux.Handle("/", withCORS(newReverseProxy("http://fe:3000")))

        certManager := &autocert.Manager{
                Prompt:     autocert.AcceptTOS,
                Cache:      autocert.DirCache("./pb_data/.autocert_cache"),
                HostPolicy: autocert.HostWhitelist(certdoms...),
        }
        // base request context used for cancelling long running requests
        // like the SSE connections
        baseCtx, cancelBaseCtx := context.WithCancel(context.Background())

        server := &http.Server{
                BaseContext: func(l net.Listener) context.Context { return baseCtx },
                TLSConfig: &tls.Config{
                        MinVersion:     tls.VersionTLS12,
                        GetCertificate: certManager.GetCertificate,
                        NextProtos:     []string{acme.ALPNProto},
                },

                ReadTimeout:       10 * time.Minute,
                ReadHeaderTimeout: 30 * time.Second,
                Addr:              fmt.Sprintf(":%d", fport),
                Handler:           publicMux,
        }

        res := make(chan error)
        SafeThread(func() {
                fmt.Printf("feglobal listening on port %d\n", fport)
                res <- server.ListenAndServeTLS("", "")
                cancelBaseCtx()
        })

        return res
}
