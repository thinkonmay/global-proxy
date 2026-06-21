package busnats

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

const (
	fetchWait    = 5 * time.Second  // poll bound so Close is noticed when idle
	retryBackoff = time.Second      // wait after a real fetch error
	ackWait      = 30 * time.Second // redelivery window for un-acked msgs
)

var _ bus.Client = (*Nats)(nil)

// Nats is a Client backed by NATS JetStream: one durable pull consumer per
// (topic, group). A message is Ack'd only after the handler returns nil; a
// handler error Naks it for redelivery (at-least-once). No DLQ — a message that
// never succeeds redelivers until its handler acks it.
type Nats struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	streams map[string]struct{} // ensured stream names
}

// New dials the NATS URLs and wraps JetStream as a bus.
func New(urls []string, logger *slog.Logger) (*Nats, error) {
	if logger == nil {
		logger = slog.Default()
	}
	nc, err := nats.Connect(strings.Join(urls, ","))
	if err != nil {
		return nil, fmt.Errorf("bus: nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}
	n := new(Nats)
	n.nc = nc
	n.js = js
	n.logger = logger
	n.streams = make(map[string]struct{})
	n.ctx, n.cancel = context.WithCancel(context.Background())
	return n, nil
}

// streamName maps a topic (subject — may contain dots) to a valid JetStream
// stream name (no dots/spaces/wildcards).
func streamName(topic string) string {
	return strings.NewReplacer(".", "_", "*", "_", ">", "_", " ", "_").Replace(topic)
}

// ensureStream idempotently creates a stream covering the topic subject.
func (n *Nats) ensureStream(ctx context.Context, topic string) error {
	name := streamName(topic)
	n.mu.Lock()
	_, ok := n.streams[name]
	n.mu.Unlock()
	if ok {
		return nil
	}
	if _, err := n.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     name,
		Subjects: []string{topic},
	}); err != nil {
		return fmt.Errorf("bus: nats stream %s: %w", name, err)
	}
	n.mu.Lock()
	n.streams[name] = struct{}{}
	n.mu.Unlock()
	return nil
}

func (n *Nats) Publish(ctx context.Context, topic string, payload []byte) error {
	if err := n.ensureStream(ctx, topic); err != nil {
		return err
	}
	if _, err := n.js.Publish(ctx, topic, payload); err != nil {
		return fmt.Errorf("bus: nats publish %s: %w", topic, err)
	}
	return nil
}

func (n *Nats) Subscribe(topic, group string, h bus.Handler, opts bus.SubscribeOptions) {
	if opts.BatchSize < 1 {
		opts.BatchSize = 1
	}
	n.wg.Go(func() {
		n.consume(topic, group, h, opts)
	})
}

func (n *Nats) consume(topic, group string, h bus.Handler, opts bus.SubscribeOptions) {
	if err := n.ensureStream(n.ctx, topic); err != nil {
		n.logger.Error("bus: nats ensure stream", "topic", topic, "err", err)
		return
	}
	// A durable shared by N subscribers = competing consumers within a group.
	cons, err := n.js.CreateOrUpdateConsumer(n.ctx, streamName(topic), jetstream.ConsumerConfig{
		Durable:   group,
		AckPolicy: jetstream.AckExplicitPolicy,
		AckWait:   ackWait,
		// Deliver only messages published after the durable is first created —
		// matches the redis backend ($ start). The durable then resumes from its
		// last ack across restarts.
		DeliverPolicy: jetstream.DeliverNewPolicy,
	})
	if err != nil {
		n.logger.Error("bus: nats consumer", "topic", topic, "group", group, "err", err)
		return
	}

	wait := fetchWait
	if opts.Linger > 0 {
		wait = opts.Linger
	}

	// Concurrency caps the handler batches in flight (sem); 0 leaves it uncapped
	// (a goroutine per fetched batch). A bounded sem also backpressures the fetch
	// loop, so the pool can't be outrun.
	var sem chan struct{}
	if opts.Concurrency >= 1 {
		sem = make(chan struct{}, opts.Concurrency)
	}
	var wg sync.WaitGroup

	for n.ctx.Err() == nil {
		batch, err := cons.Fetch(opts.BatchSize, jetstream.FetchMaxWait(wait))
		if err != nil {
			if n.ctx.Err() != nil {
				break
			}
			n.logger.Error("bus: nats fetch", "topic", topic, "group", group, "err", err)
			time.Sleep(retryBackoff)
			continue
		}

		var msgs []jetstream.Msg
		for msg := range batch.Messages() {
			msgs = append(msgs, msg)
		}
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) {
			n.logger.Error("bus: nats fetch batch", "topic", topic, "group", group, "err", err)
		}
		if len(msgs) == 0 {
			continue
		}

		if sem != nil {
			sem <- struct{}{} // block once the pool is full
		}
		wg.Go(func() {
			if sem != nil {
				defer func() { <-sem }()
			}
			n.handle(topic, group, h, msgs)
		})
	}
	wg.Wait() // let in-flight handlers ack/nak before the consumer exits
}

// handle runs h for one fetched batch and applies the per-message verdict:
// errs[i] nil => Ack, non-nil => Nak (redelivered).
func (n *Nats) handle(topic, group string, h bus.Handler, msgs []jetstream.Msg) {
	payloads := make([][]byte, len(msgs))
	for i, m := range msgs {
		payloads[i] = m.Data()
	}
	errs := safeHandle(n.ctx, h, payloads)
	var failed int
	for i, m := range msgs {
		if bus.Failed(errs, i) {
			failed++
			_ = m.Nak()
		} else {
			_ = m.Ack()
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
		n.logger.Error("bus: handler failed",
			"topic", topic, "group", group, "batch", len(payloads), "failed", failed, "err", firstErr)
	}
}

// safeHandle runs h, converting a panic into a per-message failure so a bad
// payload nacks its batch instead of crashing the consumer.
func safeHandle(ctx context.Context, h bus.Handler, payloads [][]byte) (errs []error) {
	defer func() {
		if rec := recover(); rec != nil {
			errs = bus.Each(len(payloads), fmt.Errorf("handler panic: %v", rec))
		}
	}()
	return h(ctx, payloads)
}

// Ping reports whether the NATS connection is alive.
func (n *Nats) Ping() error {
	if n.nc.IsClosed() {
		return bus.ErrClosed
	}
	if _, err := n.nc.RTT(); err != nil {
		return err
	}
	return nil
}

// Close stops all consumers, waits for in-flight batches, then closes the
// connection.
func (n *Nats) Close() error {
	n.cancel()
	n.wg.Wait()
	n.nc.Close()
	return nil
}
