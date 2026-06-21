// Package bus provides a type-safe pub/sub event bus over codec-agnostic byte transports.
package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Client interface {
	Publish(ctx context.Context, topic string, payload []byte) error
	Subscribe(topic, group string, h Handler, opts SubscribeOptions)

	Ping() error
	Close() error
}

// Handler consumes a batch of raw payloads and returns a per-payload verdict:
// result[i] reports payloads[i]'s outcome — nil acks it, non-nil naks it
// (redelivered). A nil or short slice acks the unreported indices.
type Handler func(ctx context.Context, payloads [][]byte) []error

// Failed reports whether payload i was nak'd (errs[i] set). Indices past the
// slice are treated as acked.
func Failed(errs []error, i int) bool {
	return i < len(errs) && errs[i] != nil
}

// Each builds a uniform verdict for an all-or-nothing batch handler: nil err
// acks all, else naks all.
func Each(n int, err error) []error {
	if err == nil {
		return nil
	}
	errs := make([]error, n)
	for i := range errs {
		errs[i] = err
	}
	return errs
}

// SubscribeOptions controls how a transport groups and parallelizes delivery.
type SubscribeOptions struct {
	BatchSize   int           // flush once the batch holds this many payloads (min 1)
	Linger      time.Duration // max wait after the first payload before flushing a partial batch
	Concurrency int           // max handler invocations in flight; 0 = unlimited, 1 = serial

	// JetStream (NATS backend only). DeliverNew=false (default) uses DeliverAll so
	// messages published before the consumer exists are not skipped.
	DeliverNew bool
	// MaxDeliver caps redelivery attempts before the message is copied to DLQ (default 5).
	MaxDeliver int
	// DisableDLQ skips terminal DLQ publish (e.g. usage batches with their own dedupe).
	DisableDLQ bool
}

type SubscribeOption func(*SubscribeOptions)

// ErrClosed is returned by Publish after Close.
var ErrClosed = errors.New("bus: closed")

// WithBatchSize delivers payloads in batches of up to n (pair with WithLinger to flush partials).
func WithBatchSize(n int) SubscribeOption {
	return func(o *SubscribeOptions) {
		if n > 1 {
			o.BatchSize = n
		}
	}
}

// WithLinger flushes a partial batch d after its first payload arrives.
func WithLinger(d time.Duration) SubscribeOption {
	return func(o *SubscribeOptions) {
		if d > 0 {
			o.Linger = d
		}
	}
}

// WithConcurrency caps in-flight handlers at n, so a large backlog drains
// through a fixed pool. Default (unset) is unlimited; n=1 makes delivery serial.
func WithConcurrency(n int) SubscribeOption {
	return func(o *SubscribeOptions) {
		if n >= 1 {
			o.Concurrency = n
		}
	}
}

// WithDeliverNew delivers only messages published after the durable consumer is
// created (JetStream DeliverNew). Default is DeliverAll.
func WithDeliverNew() SubscribeOption {
	return func(o *SubscribeOptions) {
		o.DeliverNew = true
	}
}

// WithMaxDeliver sets JetStream MaxDeliver before DLQ routing (default 5).
func WithMaxDeliver(n int) SubscribeOption {
	return func(o *SubscribeOptions) {
		if n >= 1 {
			o.MaxDeliver = n
		}
	}
}

// WithoutDLQ disables terminal publish to <topic>.dlq after max deliveries.
func WithoutDLQ() SubscribeOption {
	return func(o *SubscribeOptions) {
		o.DisableDLQ = true
	}
}

// Topic binds a name to payload type T at compile time.
type Topic[T any] struct {
	Name string
}

func NewTopic[T any](name string) Topic[T] {
	return Topic[T]{Name: name}
}

// Publish marshals payload and fans it out to every group subscribed to topic.
func Publish[T any](ctx context.Context, c Client, topic Topic[T], payload T) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("bus: marshal %s: %w", topic.Name, err)
	}
	return c.Publish(ctx, topic.Name, data)
}

// Subscribe registers h under group for topic, invoked once per payload.
// WithConcurrency caps the worker pool (default unlimited); WithBatchSize/WithLinger are ignored.
func Subscribe[T any](
	c Client,
	topic Topic[T],
	group string,
	h func(ctx context.Context, payload T) error,
	opts ...SubscribeOption,
) {
	options := buildOptions(opts)
	options.BatchSize = 1 // per-message semantics
	c.Subscribe(topic.Name, group, func(ctx context.Context, raws [][]byte) []error {
		errs := make([]error, len(raws))
		for i, raw := range raws {
			var payload T
			if err := json.Unmarshal(raw, &payload); err != nil {
				errs[i] = fmt.Errorf("bus: unmarshal %s: %w", topic.Name, err)
				continue
			}
			errs[i] = h(ctx, payload)
		}
		return errs
	}, options)
}

// SubscribeBatch registers h under group for topic; batches are shaped by
// WithBatchSize/WithLinger (default one payload per call).
func SubscribeBatch[T any](
	c Client,
	topic Topic[T],
	group string,
	h func(ctx context.Context, payloads []T) []error,
	opts ...SubscribeOption,
) {
	options := buildOptions(opts)
	c.Subscribe(topic.Name, group, func(ctx context.Context, raws [][]byte) []error {
		errs := make([]error, len(raws))
		// A payload that won't unmarshal is a permanent poison: mark it failed and
		// keep it out of the typed slice handed to h.
		payloads := make([]T, 0, len(raws))
		idx := make([]int, 0, len(raws)) // payloads[j] came from raws[idx[j]]
		for i, raw := range raws {
			var p T
			if err := json.Unmarshal(raw, &p); err != nil {
				errs[i] = fmt.Errorf("bus: unmarshal %s: %w", topic.Name, err)
				continue
			}
			payloads = append(payloads, p)
			idx = append(idx, i)
		}
		if len(payloads) == 0 {
			return errs
		}
		// h's verdict aligns to payloads; map each result back to its raw index.
		res := h(ctx, payloads)
		for j, i := range idx {
			if j < len(res) {
				errs[i] = res[j]
			}
		}
		return errs
	}, options)
}

// buildOptions applies opts over the defaults (one payload per call, serial).
func buildOptions(opts []SubscribeOption) SubscribeOptions {
	options := SubscribeOptions{BatchSize: 1}
	for _, opt := range opts {
		opt(&options)
	}
	return options
}
