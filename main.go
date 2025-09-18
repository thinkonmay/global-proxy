package main

import (
	"context"
	"crypto/tls"
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
	certdoms     = StringSlice{}
	sport, qport = 0, 0
	analyticCred = ""
	cache        = analyticCache{
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
	psport := flag.Int("sport", 445, "secure global port")
	pqport := flag.Int("qport", 3000, "unsecure query port")
	flag.Var(&certdoms, "dom", "Specify multiple string values (e.g., -s val1 -s val2)")
	panalyticCred := flag.String("cred", "", "report analytics credential")
	flag.Parse()

	if psport != nil {
		sport = *psport
	}
	if pqport != nil {
		qport = *pqport
	}
	if panalyticCred != nil {
		analyticCred = *panalyticCred
	}
}

func main() {
	PrepareReportHandler()
	stop1 := StartGlobalProxy()
	stop2 := StartQueryAnalytics()

	sigchan := make(chan os.Signal, 16)
	signal.Notify(sigchan, syscall.SIGTERM, os.Interrupt)

	select {
	case err := <-stop1:
		fmt.Printf("receive error %v from supabase proxy\n", err)
	case err := <-stop2:
		fmt.Printf("receive error %v from query analytics\n", err)
	case sig := <-sigchan:
		fmt.Printf("receive signal %s from os\n", sig.String())
	}
}

func StartGlobalProxy() <-chan error {
	if len(certdoms) == 0 {
		fmt.Println("no certdoms provided, don't start global proxy")
		return make(<-chan error)
	}

	apiProxy := newReverseProxy("http://localhost:3001")
	rootProxy := newReverseProxy("http://localhost:3002")
	publicMux.Handle("/api/", apiProxy)
	publicMux.Handle("/", rootProxy)

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
		fmt.Printf("global proxy listening on port %d\n",sport)
		res <- server.ListenAndServe()
		cancelBaseCtx()
	})
	return res
}

func PrepareReportHandler() {
	publicMux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if credential := r.Header.Get("Authorization"); credential != analyticCred {
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
}

func StartQueryAnalytics() <-chan error {
	privateMux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		if credential := r.Header.Get("Authorization"); credential != analyticCred {
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

	res := make(chan error)
	SafeThread(func() {
		fmt.Printf("query analytics listening on port %d\n",qport)
		res <- privateServer.ListenAndServe()
	})
	return res
}
