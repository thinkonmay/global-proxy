package event

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const (
	clientBuffer = 16               // per-client queue; full => event dropped for that client
	heartbeat    = 10 * time.Second // keepalive comment so idle conns/proxies stay open
)

// client is one connected /v1/event/{domain} stream: a queue drained by its own
// Serve loop.
type client struct {
	domain    string
	recipient string
	ch        chan model.EventRaw
}

// Hub routes events to connected clients by (domain, recipient). Live,
// best-effort: a client that can't keep up drops events rather than stalling the
// bus.
type Hub struct {
	mu      sync.RWMutex
	clients map[*client]struct{}
	seq     atomic.Uint64
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*client]struct{})}
}

// Dispatch is the bus handler: it routes one event to every client on its domain
// (recipient targets one user's streams; empty broadcasts to the domain). The
// send is non-blocking — a client whose buffer is full drops the event rather
// than stalling the bus.
func (h *Hub) Dispatch(_ context.Context, e model.EventRaw) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		if e.Domain != c.domain {
			continue
		}
		if e.Recipient != "" && e.Recipient != c.recipient {
			continue
		}
		select {
		case c.ch <- e:
		default: // slow client: drop, don't block the bus
		}
	}
	return nil
}

// ServeFor holds the connection open and streams the domain's events for
// recipient until the client disconnects. The caller derives domain (from the
// route) and recipient (from authentication) — the hub stays a generic transport
// and does not inspect the request identity.
func (h *Hub) ServeFor(w http.ResponseWriter, r *http.Request, domain, recipient string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	c := h.add(domain, recipient)
	defer h.remove(c)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-c.ch:
			h.writeMsg(w, e)
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ":keepalive\n\n")
			flusher.Flush()
		}
	}
}

// writeMsg renders one event: the payload is written verbatim as the SSE data
// field.
//
//	id:{seq}\n data:{json}\n \n
func (h *Hub) writeMsg(w io.Writer, e model.EventRaw) {
	if len(e.Data) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "id:%d\ndata:%s\n\n", h.seq.Add(1), e.Data)
}

func (h *Hub) add(domain, recipient string) *client {
	c := &client{domain: domain, recipient: recipient, ch: make(chan model.EventRaw, clientBuffer)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	return c
}

func (h *Hub) remove(c *client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// Clients reports the number of connected streams.
func (h *Hub) Clients() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
