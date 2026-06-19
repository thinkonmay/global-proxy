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
	natsFetchWait       = 5 * time.Second  // poll bound so Close is noticed when idle
	natsRetryBackoff    = time.Second      // wait after a real fetch error
	natsAckWait         = 30 * time.Second // redelivery window for un-acked msgs
	natsDefaultMaxDeliv = 5                // handler attempts before a msg goes to DLQ
)

var _ bus.Client = (*Nats)(nil)

// Nats is a Client backed by NATS JetStream: one durable pull consumer per
// (topic, group). Messages are Ack'd only after the handler returns nil
// (at-least-once); a handler error Naks the batch for redelivery. After
// maxDeliver failed attempts a message is moved to <topic>.DLQ and Ack'd, so a
// poison message can't crash-loop the consumer forever.
type Nats struct {
	nc         *nats.Conn
	js         jetstream.JetStream
	logger     *slog.Logger
	maxDeliver int // <=0 disables the DLQ cap (unlimited redelivery)
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	mu      sync.Mutex
	streams map[string]struct{} // ensured stream names
}

// Option configures the bus.
type Option func(*Nats)

// WithMaxDeliver sets how many times a message is handed to the handler before
// it is routed to the DLQ. n <= 0 disables the cap (infinite redelivery).
func WithMaxDeliver(n int) Option {
	return func(c *Nats) { c.maxDeliver = n }
}

// Connect dials the NATS URLs and wraps JetStream as a bus.
func Connect(urls []string, logger *slog.Logger, opts ...Option) (*Nats, error) {
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
	n.maxDeliver = natsDefaultMaxDeliv
	n.streams = make(map[string]struct{})
	n.ctx, n.cancel = context.WithCancel(context.Background())
	for _, opt := range opts {
		opt(n)
	}
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
		AckWait:   natsAckWait,
		// Deliver only messages published after the durable is first created —
		// matches the redis backend ($ start). The durable then resumes from its
		// last ack across restarts.
		DeliverPolicy: jetstream.DeliverNewPolicy,
	})
	if err != nil {
		n.logger.Error("bus: nats consumer", "topic", topic, "group", group, "err", err)
		return
	}

	wait := natsFetchWait
	if opts.Linger > 0 {
		wait = opts.Linger
	}

	for n.ctx.Err() == nil {
		batch, err := cons.Fetch(opts.BatchSize, jetstream.FetchMaxWait(wait))
		if err != nil {
			if n.ctx.Err() != nil {
				return
			}
			n.logger.Error("bus: nats fetch", "topic", topic, "group", group, "err", err)
			time.Sleep(natsRetryBackoff)
			continue
		}

		// Split exhausted (poison) messages off to the DLQ before handling.
		var live []jetstream.Msg
		var attempt int
		for msg := range batch.Messages() {
			deliv := numDelivered(msg)
			if n.maxDeliver > 0 && deliv > n.maxDeliver {
				n.toDLQ(topic, group, msg, deliv)
				continue
			}
			if deliv > attempt {
				attempt = deliv
			}
			live = append(live, msg)
		}
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) {
			n.logger.Error("bus: nats fetch batch", "topic", topic, "group", group, "err", err)
		}
		if len(live) == 0 {
			continue
		}

		payloads := make([][]byte, len(live))
		for i, m := range live {
			payloads[i] = m.Data()
		}

		// Per-message verdict: errs[i] nil => Ack msg i, non-nil => Nak it
		// (redelivered; NumDelivered climbs, eventually crossing maxDeliver -> DLQ).
		errs := safeHandle(n.ctx, h, payloads)
		var failed int
		for i, m := range live {
			if bus.Failed(errs, i) {
				failed++
				_ = m.Nak()
			} else {
				_ = m.Ack()
			}
		}
		if failed > 0 {
			n.logger.Error("bus: handler failed",
				"topic", topic, "group", group, "batch", len(payloads), "failed", failed, "attempt", attempt)
		}
	}
}

// toDLQ republishes a poison message to <topic>.DLQ and Acks it off the main
// stream. If the DLQ publish fails the message is left un-acked so it is retried
// rather than lost.
func (n *Nats) toDLQ(topic, group string, msg jetstream.Msg, deliv int) {
	dlq := bus.DlqTopic(topic)
	if err := n.ensureStream(n.ctx, dlq); err != nil {
		n.logger.Error("bus: nats dlq stream", "topic", dlq, "err", err)
		return
	}
	if _, err := n.js.Publish(n.ctx, dlq, msg.Data()); err != nil {
		n.logger.Error("bus: nats dlq publish", "topic", dlq, "err", err)
		return
	}
	n.logger.Warn("bus: message routed to DLQ",
		"topic", topic, "group", group, "dlq", dlq, "deliveries", deliv)
	_ = msg.Ack()
}

// numDelivered returns the JetStream delivery count for a message (1 on first
// delivery), or 1 if metadata is unavailable.
func numDelivered(msg jetstream.Msg) int {
	md, err := msg.Metadata()
	if err != nil || md == nil {
		return 1
	}
	return int(md.NumDelivered)
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
