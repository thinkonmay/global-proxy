package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	certdoms                   = StringSlice{}
	sport, qport, rport, gport = 0, 0, 0, 0
	analyticCred               = ""
	cache                      = analyticCache{
		nodeMap: make(map[string]*nodeCache),
		mut:     &sync.Mutex{},
	}

	publicMux  = http.NewServeMux()
	privateMux = http.NewServeMux()
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
	psport := flag.Int("sport", 0, "secure global port")
	pqport := flag.Int("qport", 0, "unsecure query port")
	prport := flag.Int("rport", 0, "rybbit port")
	pgport := flag.Int("gport", 0, "g4global port")
	flag.Var(&certdoms, "dom", "Specify multiple string values (e.g., -s val1 -s val2)")
	panalyticCred := flag.String("cred", "", "report analytics credential")
	flag.Parse()

	if psport != nil {
		sport = *psport
	}
	if pqport != nil {
		qport = *pqport
	}
	if prport != nil {
		rport = *prport
	}
	if pgport != nil {
		gport = *pgport
	}
	if panalyticCred != nil {
		analyticCred = *panalyticCred
	}
}

func main() {
	PrepareReportHandler()

	stop1 := StartGlobalProxy()
	stop2 := StartQueryAnalytics()
	stop3 := StartRybbit()
	stop4 := StartG4Global()

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

	publicMux.Handle("/", withCORS(newReverseProxy("http://kong:8000")))

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
		Addr:              fmt.Sprintf(":%d", sport),
		Handler:           publicMux,
	}
	res := make(chan error)
	SafeThread(func() {
		fmt.Printf("global proxy listening on port %d\n", sport)
		res <- server.ListenAndServeTLS("", "")
		cancelBaseCtx()
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
			if nodeData, found := cache.nodeMap[destnode]; !found {
				return
			} else {
				nodeData.mut.Lock()
				defer nodeData.mut.Unlock()
				if time.Since(nodeData.typeMap[desttyp].timestamp) > 1*time.Minute {
					return
				}
				w.WriteHeader(200)
				w.Write(nodeData.typeMap[desttyp].data)
				return
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
			return
		}
		w.WriteHeader(200)
		w.Write(res)
		return

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
