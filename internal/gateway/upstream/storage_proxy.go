package upstream

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/supabase/auth"
)

// Kong nginx parity: proxy_buffer_size 160k; proxy_buffers 64 160k.
const (
	storageProxyTimeout = 120 * time.Second
	storageBufferSize   = 160 << 10 // Kong proxy_buffer_size 160k
)

type kongBufferPool struct {
	size int
	pool sync.Pool
}

func newKongBufferPool(size int) *kongBufferPool {
	return &kongBufferPool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

func (p *kongBufferPool) Get() []byte {
	b := p.pool.Get().(*[]byte)
	return (*b)[:0]
}

func (p *kongBufferPool) Put(b []byte) {
	if cap(b) != p.size {
		return
	}
	p.pool.Put(&b)
}

var storageBufferPool = newKongBufferPool(storageBufferSize)

func registerStorageRoute(mux *http.ServeMux, cfg *config.Config, rt http.RoundTripper, keys *auth.Keys) {
	if cfg.Upstreams.Storage == "" {
		return
	}
	storage := NewProxy(cfg.Upstreams.Storage, rt, func(req *http.Request) {
		if req.Header.Get("X-Forwarded-Prefix") == "" {
			req.Header.Set("X-Forwarded-Prefix", storagePrefix)
		}
		req.URL.Path = strings.TrimPrefix(req.URL.Path, storagePrefix)
		SetForwardedHeaders(req)
	})
	if storage == nil {
		slog.Error("storage upstream invalid, /storage/v1/* disabled")
		return
	}
	storage.BufferPool = storageBufferPool
	h := auth.StorageAuth(keys)(timed(storage, storageProxyTimeout))
	mux.Handle(storagePrefix+"/", h)
}
