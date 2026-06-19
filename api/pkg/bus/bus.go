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

// Handler consumes a batch of raw payloads (one payload unless batch options are
// set) and returns a per-payload verdict: result[i] reports payloads[i]'s
// outcome — nil acks it, non-nil naks it (redelivered, eventually DLQ'd). A nil
// or short slice acks the unreported indices, so `return nil` means "all ok".
type Handler func(ctx context.Context, payloads [][]byte) []error

// Failed reports whether payload i was nak'd by a Handler verdict (errs[i] set).
// Indices past the slice are treated as acked. Transports use this to decide
// ack vs nak per message.
func Failed(errs []error, i int) bool {
	return i < len(errs) && errs[i] != nil
}

// Each builds a uniform per-message verdict for an all-or-nothing batch handler
// (e.g. one batched INSERT): nil err -> nil (ack all), else err repeated n times
// (nak all).
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

func DlqTopic(topic string) string {
	return topic + ".DLQ"
}

// SubscribeOptions controls how a transport groups payloads before delivery.
type SubscribeOptions struct {
	BatchSize int           // flush once the batch holds this many payloads (min 1)
	Linger    time.Duration // max wait after the first payload before flushing a partial batch
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
func Subscribe[T any](
	c Client,
	topic Topic[T],
	group string,
	h func(ctx context.Context, payload T) error,
) {
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
	}, SubscribeOptions{BatchSize: 1})
}

// SubscribeBatch registers h under group for topic; batches are shaped by WithBatchSize/WithLinger (default one payload per call).
func SubscribeBatch[T any](
	c Client,
	topic Topic[T],
	group string,
	h func(ctx context.Context, payloads []T) []error,
	opts ...SubscribeOption,
) {
	options := SubscribeOptions{BatchSize: 1, Linger: 0}
	for _, opt := range opts {
		opt(&options)
	}
	c.Subscribe(topic.Name, group, func(ctx context.Context, raws [][]byte) []error {
		errs := make([]error, len(raws))
		// Decode the batch; a payload that won't unmarshal is a permanent poison —
		// mark it failed and keep it out of the typed slice handed to h.
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
