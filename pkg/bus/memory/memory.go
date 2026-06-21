package busmemory

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// subBuffer is the per-subscription channel capacity. A full buffer blocks
// Publish (backpressure) until consumers catch up.
const subBuffer = 1024

// subscription is one subscription: a queue drained by its worker pool.
type subscription struct {
	ch chan []byte
}

// consumerGroup holds a group's subscriptions and a round-robin cursor for
// competing-consumer delivery within the group.
type consumerGroup struct {
	subs []*subscription
	next atomic.Uint64
}

var _ bus.Client = (*Memory)(nil)

// Memory is an in-process Client. Each subscription drains its queue through a
// worker pool (WithConcurrency, default one) that batches per SubscribeOptions;
// handler errors are logged and dropped.
type Memory struct {
	mu        sync.RWMutex
	topics    map[string]map[string]*consumerGroup // topic -> group -> subscriptions
	closed    bool
	inflight  sync.WaitGroup // published payloads not yet handled
	consumers sync.WaitGroup // consumer goroutines
	logger    *slog.Logger
}

func New(logger *slog.Logger) *Memory {
	if logger == nil {
		logger = slog.Default()
	}
	m := new(Memory)
	m.topics = make(map[string]map[string]*consumerGroup)
	m.logger = logger
	return m
}

func (m *Memory) Subscribe(topic, group string, h bus.Handler, opts bus.SubscribeOptions) {
	if opts.BatchSize < 1 {
		opts.BatchSize = 1
	}
	sub := &subscription{ch: make(chan []byte, subBuffer)}

	m.mu.Lock()
	groups, ok := m.topics[topic]
	if !ok {
		groups = make(map[string]*consumerGroup)
		m.topics[topic] = groups
	}
	g, ok := groups[group]
	if !ok {
		g = new(consumerGroup)
		groups[group] = g
	}
	g.subs = append(g.subs, sub)
	m.mu.Unlock()

	m.consumers.Go(func() {
		m.consume(topic, group, sub, h, opts)
	})
}

// Publish enqueues payload to one subscription per group (round-robin).
// Sends happen under the read lock so Close cannot close a channel mid-send.
func (m *Memory) Publish(_ context.Context, topic string, payload []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return bus.ErrClosed
	}
	for _, g := range m.topics[topic] {
		i := (g.next.Add(1) - 1) % uint64(len(g.subs))
		m.inflight.Add(1)
		g.subs[i].ch <- payload
	}
	return nil
}

// consume drains a subscription and dispatches each batch to h. Concurrency
// caps the handlers in flight (sem); 0 leaves it uncapped (a goroutine per
// batch). Concurrency 1 keeps delivery serial and FIFO.
func (m *Memory) consume(topic, group string, sub *subscription, h bus.Handler, opts bus.SubscribeOptions) {
	// Batches span multiple publishes, so handlers get a fresh context rather
	// than any single publisher's.
	ctx := context.Background()
	var sem chan struct{}
	if opts.Concurrency >= 1 {
		sem = make(chan struct{}, opts.Concurrency)
	}
	var wg sync.WaitGroup
	for {
		first, ok := <-sub.ch
		if !ok {
			break
		}
		batch := fillBatch(sub, first, opts)
		if sem != nil {
			sem <- struct{}{} // block once the pool is full
		}
		wg.Go(func() {
			if sem != nil {
				defer func() { <-sem }()
			}
			m.handle(ctx, topic, group, h, batch)
		})
	}
	wg.Wait() // let in-flight handlers finish before the consumer exits
}

// handle runs h for one batch. In-process bus has no redelivery, so a
// per-message failure is logged and dropped (the verdict matters only to
// durable transports).
func (m *Memory) handle(ctx context.Context, topic, group string, h bus.Handler, batch [][]byte) {
	errs := h(ctx, batch)
	var failed int
	for i := range batch {
		if bus.Failed(errs, i) {
			failed++
		}
	}
	if failed > 0 {
		var firstErr error
		for _, err := range errs {
			if err != nil {
				firstErr = err
				break
			}
		}
		m.logger.ErrorContext(ctx, "bus: handler failed",
			"topic", topic, "group", group, "batch", len(batch), "failed", failed, "err", firstErr)
	}
	m.inflight.Add(-len(batch))
}

// fillBatch grows a batch from first until BatchSize is reached, Linger
// expires, or the subscription closes — whichever comes first.
func fillBatch(sub *subscription, first []byte, opts bus.SubscribeOptions) [][]byte {
	batch := [][]byte{first}
	if opts.BatchSize <= 1 {
		return batch
	}
	timer := time.NewTimer(opts.Linger)
	defer timer.Stop()
	for len(batch) < opts.BatchSize {
		select {
		case payload, more := <-sub.ch:
			if !more {
				return batch
			}
			batch = append(batch, payload)
		case <-timer.C:
			return batch
		}
	}
	return batch
}

// Wait blocks until every published payload has been handled. Use in tests.
func (m *Memory) Wait() {
	m.inflight.Wait()
}

// Ping reports whether the bus accepts publishes.
func (m *Memory) Ping() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return bus.ErrClosed
	}
	return nil
}

// Close rejects further publishes, lets consumers drain their queues, and
// returns once they exit. Use on shutdown.
func (m *Memory) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	for _, groups := range m.topics {
		for _, g := range groups {
			for _, sub := range g.subs {
				close(sub.ch)
			}
		}
	}
	m.mu.Unlock()
	m.consumers.Wait()
	return nil
}
