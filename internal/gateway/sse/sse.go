package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const (
	sseClientBuffer = 16               // per-client queue; full => event dropped for that client
	sseHeartbeat    = 25 * time.Second // keepalive comment so idle conns/proxies stay open
)

// sseClient is one connected SSE stream: a queue drained by its own Serve loop.
type sseClient struct {
	recipient string
	ch        chan model.SSERaw
}

// Hub routes events to connected clients by recipient. Live, best-effort: a
// client that can't keep up drops events rather than stalling the bus.
type Hub struct {
	mu      sync.RWMutex
	clients map[*sseClient]struct{}
	seq     atomic.Uint64
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*sseClient]struct{})}
}

// Dispatch is the bus handler: it routes one event to every matching client
// (recipient targets one user's streams; empty broadcasts to all). The send is
// non-blocking — a client whose buffer is full drops the event rather than
// stalling the bus.
func (h *Hub) Dispatch(_ context.Context, e model.SSERaw) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
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

// ServeFor holds the connection open and streams events for recipient until the
// client disconnects. The caller derives recipient (e.g. from authentication) —
// the hub stays a generic transport and does not inspect the request identity.
func (h *Hub) ServeFor(w http.ResponseWriter, r *http.Request, recipient string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	c := h.add(recipient)
	defer h.remove(c)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ticker := time.NewTicker(sseHeartbeat)
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

// writeMsg renders one message in the SSE wire format (tdd §2.4.1):
//
//	id:{seq}\n data:{json}\n \n
func (h *Hub) writeMsg(w io.Writer, e model.SSERaw) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "id:%d\ndata:%s\n\n", h.seq.Add(1), data)
}

func (h *Hub) add(recipient string) *sseClient {
	c := &sseClient{recipient: recipient, ch: make(chan model.SSERaw, sseClientBuffer)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	return c
}

func (h *Hub) remove(c *sseClient) {
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
