package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/rs/cors"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v3"
)

type RouteEntry struct {
	Upstream string            `yaml:"upstream"`
	Paths    map[string]string `yaml:"paths"`
}

type Config struct {
	CertDir string `yaml:"cert_dir"`
	Email   string `yaml:"email"`

	Domains map[string]RouteEntry `yaml:"domains"`

	Internal struct {
		DomainSuffix string            `yaml:"domain_suffix"`
		AllowedCIDRs []string          `yaml:"allowed_cidrs"`
		Routes       map[string]RouteEntry `yaml:"routes"`
	} `yaml:"internal"`
}

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/gateway/config.yaml"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	if cfg.CertDir == "" {
		cfg.CertDir = "/var/lib/gateway/certs"
	}

	// Parse allowed CIDRs for internal services
	var allowedNets []*net.IPNet
	for _, cidr := range cfg.Internal.AllowedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("invalid CIDR %q: %v", cidr, err)
		}
		allowedNets = append(allowedNets, ipNet)
	}

	// Build reverse proxies for public domains (thinkmay.net → website)
	publicProxies := make(map[string]http.Handler)
	var allDomains []string
	for domain, route := range cfg.Domains {
		if len(route.Paths) > 0 {
			mux := http.NewServeMux()
			for path, upstream := range route.Paths {
				target, err := url.Parse(upstream)
				if err != nil {
					log.Fatalf("invalid upstream %q for path %q on domain %q: %v", upstream, path, domain, err)
				}
				mux.Handle(path, httputil.NewSingleHostReverseProxy(target))
				log.Printf("route: %s%s → %s", domain, path, upstream)
			}
			publicProxies[domain] = mux
		} else {
			target, err := url.Parse(route.Upstream)
			if err != nil {
				log.Fatalf("invalid upstream %q for domain %q: %v", route.Upstream, domain, err)
			}
			publicProxies[domain] = httputil.NewSingleHostReverseProxy(target)
			log.Printf("route: %s → %s", domain, route.Upstream)
		}
		allDomains = append(allDomains, domain)
	}

	// Build reverse proxies for internal routes (*.api.thinkmay.net → services)
	internalProxies := make(map[string]http.Handler)
	suffix := "." + cfg.Internal.DomainSuffix
	for name, route := range cfg.Internal.Routes {
		fqdn := name + suffix
		if len(route.Paths) > 0 {
			mux := http.NewServeMux()
			for path, upstream := range route.Paths {
				target, err := url.Parse(upstream)
				if err != nil {
					log.Fatalf("invalid upstream %q for path %q on route %q: %v", upstream, path, name, err)
				}
				mux.Handle(path, httputil.NewSingleHostReverseProxy(target))
				log.Printf("route: %s%s → %s [ip-restricted]", fqdn, path, upstream)
			}
			internalProxies[name] = mux
		} else {
			target, err := url.Parse(route.Upstream)
			if err != nil {
				log.Fatalf("invalid upstream %q for route %q: %v", route.Upstream, name, err)
			}
			internalProxies[name] = httputil.NewSingleHostReverseProxy(target)
			log.Printf("route: %s → %s [ip-restricted]", fqdn, route.Upstream)
		}
		allDomains = append(allDomains, fqdn)
	}

	log.Printf("allowed CIDRs for internal routes: %v", cfg.Internal.AllowedCIDRs)

	// Initialize Coraza WAF
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
			`),
	)
	if err != nil {
		log.Fatalf("failed to initialize WAF: %v", err)
	}

	// Main handler
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := stripPort(r.Host)

		// 1. Check public domains
		if proxy, ok := publicProxies[host]; ok {
			proxy.ServeHTTP(w, r)
			return
		}

		// 2. Check internal routes (*.api.thinkmay.net)
		if strings.HasSuffix(host, suffix) {
			name := strings.TrimSuffix(host, suffix)
			if proxy, ok := internalProxies[name]; ok {
				clientIP := extractClientIP(r)
				if !isAllowed(clientIP, allowedNets) {
					log.Printf("BLOCKED %s → %s from %s", host, name, clientIP)
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
				proxy.ServeHTTP(w, r)
				return
			}
		}

		http.Error(w, "404 Not Found", http.StatusNotFound)
	})

	handler := txhttp.WrapHandler(waf, baseHandler)

	// Apply CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"*"},
	})
	handler = c.Handler(handler)

	// autocert manager for Let's Encrypt
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      cfg.Email,
		HostPolicy: autocert.HostWhitelist(allDomains...),
		Cache:      autocert.DirCache(cfg.CertDir),
	}

	// HTTPS server
	tlsSrv := &http.Server{
		Addr:    ":443",
		Handler: handler,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}

	// HTTP server — serves ACME challenges, redirects everything else to HTTPS
	go func() {
		httpSrv := &http.Server{
			Addr: ":80",
			Handler: certManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})),
		}
		log.Fatal(httpSrv.ListenAndServe())
	}()

	log.Printf("gateway listening on :80 (HTTP) and :443 (HTTPS)")
	log.Fatal(tlsSrv.ListenAndServeTLS("", ""))
}

// stripPort removes the port from a host:port string.
func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // no port
	}
	return host
}

// extractClientIP returns the client IP, respecting X-Forwarded-For and X-Real-IP.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// isAllowed checks if the IP is in one of the allowed CIDRs.
func isAllowed(ip string, nets []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
