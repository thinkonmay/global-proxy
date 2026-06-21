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
	fetchWait       = 5 * time.Second
	retryBackoff    = time.Second
	ackWait         = 30 * time.Second
	defaultMaxDeliver = 5
)

var _ bus.Client = (*Nats)(nil)

// Nats is a Client backed by NATS JetStream: one durable pull consumer per
// (topic, group). Handlers return nil to Ack; non-nil Nak for redelivery.
// After MaxDeliver failures the payload is copied to <topic>.dlq and Ack'd.
type Nats struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	streams map[string]struct{}
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

func streamName(topic string) string {
	return strings.NewReplacer(".", "_", "*", "_", ">", "_", " ", "_").Replace(topic)
}

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

	maxDeliver := opts.MaxDeliver
	if maxDeliver < 1 {
		maxDeliver = defaultMaxDeliver
	}
	deliverPolicy := jetstream.DeliverAllPolicy
	if opts.DeliverNew {
		deliverPolicy = jetstream.DeliverNewPolicy
	}

	cons, err := n.js.CreateOrUpdateConsumer(n.ctx, streamName(topic), jetstream.ConsumerConfig{
		Durable:       group,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       ackWait,
		DeliverPolicy: deliverPolicy,
		MaxDeliver:    maxDeliver,
	})
	if err != nil {
		n.logger.Error("bus: nats consumer", "topic", topic, "group", group, "err", err)
		return
	}

	wait := fetchWait
	if opts.Linger > 0 {
		wait = opts.Linger
	}

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
			sem <- struct{}{}
		}
		wg.Go(func() {
			if sem != nil {
				defer func() { <-sem }()
			}
			n.handle(topic, group, h, msgs, opts, maxDeliver)
		})
	}
	wg.Wait()
}

func (n *Nats) handle(topic, group string, h bus.Handler, msgs []jetstream.Msg, opts bus.SubscribeOptions, maxDeliver int) {
	payloads := make([][]byte, len(msgs))
	for i, m := range msgs {
		payloads[i] = m.Data()
	}
	errs := safeHandle(n.ctx, h, payloads)
	dlqTopic := topic + ".dlq"
	var failed int
	for i, m := range msgs {
		if bus.Failed(errs, i) {
			failed++
			delivered := uint64(1)
			if meta, err := m.Metadata(); err == nil {
				delivered = meta.NumDelivered
			}
			if !opts.DisableDLQ && delivered >= uint64(maxDeliver) {
				if err := n.moveToDLQ(n.ctx, dlqTopic, m.Data()); err != nil {
					n.logger.Error("bus: dlq publish failed", "topic", topic, "dlq", dlqTopic, "err", err)
					_ = m.Nak()
					continue
				}
				n.logger.Warn("bus: message moved to DLQ",
					"topic", topic, "group", group, "dlq", dlqTopic, "deliveries", delivered)
				_ = m.Ack()
				continue
			}
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

func (n *Nats) moveToDLQ(ctx context.Context, dlqTopic string, payload []byte) error {
	if err := n.ensureStream(ctx, dlqTopic); err != nil {
		return err
	}
	_, err := n.js.Publish(ctx, dlqTopic, payload)
	return err
}

func safeHandle(ctx context.Context, h bus.Handler, payloads [][]byte) (errs []error) {
	defer func() {
		if rec := recover(); rec != nil {
			errs = bus.Each(len(payloads), fmt.Errorf("handler panic: %v", rec))
		}
	}()
	return h(ctx, payloads)
}

func (n *Nats) Ping() error {
	if n.nc.IsClosed() {
		return bus.ErrClosed
	}
	if _, err := n.nc.RTT(); err != nil {
		return err
	}
	return nil
}

func (n *Nats) Close() error {
	n.cancel()
	n.wg.Wait()
	n.nc.Close()
	return nil
}
