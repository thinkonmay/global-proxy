package bus_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// Unit tests for the generic layer in bus.go (codec + option funcs), no transport.
// fakeClient captures what the helpers hand to a Client.

type fakeClient struct {
	mu        sync.Mutex
	published [][]byte
	topics    []string
	handler   bus.Handler
	opts      bus.SubscribeOptions
}

func (f *fakeClient) Publish(_ context.Context, topic string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.topics = append(f.topics, topic)
	f.published = append(f.published, payload)
	return nil
}

func (f *fakeClient) Subscribe(_, _ string, h bus.Handler, opts bus.SubscribeOptions) {
	f.handler = h
	f.opts = opts
}

func (f *fakeClient) Ping() error  { return nil }
func (f *fakeClient) Close() error { return nil }

type event struct {
	ID  int    `json:"id"`
	Msg string `json:"msg"`
}

func TestPublish_MarshalsAndForwards(t *testing.T) {
	f := &fakeClient{}
	topic := bus.NewTopic[event]("orders")

	err := bus.Publish(context.Background(), f, topic, event{ID: 7, Msg: "hi"})
	require.NoError(t, err)

	require.Len(t, f.published, 1)
	require.Equal(t, []string{"orders"}, f.topics)

	var got event
	require.NoError(t, json.Unmarshal(f.published[0], &got))
	assert.Equal(t, event{ID: 7, Msg: "hi"}, got)
}

func TestPublish_MarshalErrorIsWrappedAndNotForwarded(t *testing.T) {
	f := &fakeClient{}
	// chan is not JSON-marshalable, so json.Marshal fails inside Publish.
	topic := bus.NewTopic[chan int]("bad")

	err := bus.Publish(context.Background(), f, topic, make(chan int))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bus: marshal bad")
	assert.Empty(t, f.published, "payload must not reach the Client when marshalling fails")
}

func TestSubscribe_DecodesPerPayload(t *testing.T) {
	f := &fakeClient{}
	topic := bus.NewTopic[event]("orders")

	var got []event
	bus.Subscribe(f, topic, "g", func(_ context.Context, e event) error {
		got = append(got, e)
		return nil
	})
	require.NotNil(t, f.handler, "Subscribe must register a raw handler")
	assert.Equal(t, 1, f.opts.BatchSize, "single Subscribe forces one payload per call")

	raw := [][]byte{[]byte(`{"id":1,"msg":"a"}`), []byte(`{"id":2,"msg":"b"}`)}
	errs := f.handler(context.Background(), raw)
	assert.Equal(t, []error{nil, nil}, errs, "both payloads ack")
	assert.Equal(t, []event{{ID: 1, Msg: "a"}, {ID: 2, Msg: "b"}}, got)
}

func TestSubscribe_UnmarshalErrorSkipsHandler(t *testing.T) {
	f := &fakeClient{}
	topic := bus.NewTopic[event]("orders")

	called := false
	bus.Subscribe(f, topic, "g", func(_ context.Context, _ event) error {
		called = true
		return nil
	})

	errs := f.handler(context.Background(), [][]byte{[]byte(`not json`)})
	require.Len(t, errs, 1)
	require.Error(t, errs[0], "the bad payload is nak'd")
	assert.Contains(t, errs[0].Error(), "bus: unmarshal orders")
	assert.False(t, called, "typed handler must not run when a payload fails to decode")
}

func TestSubscribeBatch_DecodesBatch(t *testing.T) {
	f := &fakeClient{}
	topic := bus.NewTopic[event]("orders")

	var got []event
	bus.SubscribeBatch(f, topic, "g", func(_ context.Context, payloads []event) []error {
		got = payloads
		return nil
	})

	raw := [][]byte{[]byte(`{"id":1,"msg":"a"}`), []byte(`{"id":2,"msg":"b"}`)}
	errs := f.handler(context.Background(), raw)
	assert.Equal(t, []error{nil, nil}, errs, "both payloads ack")
	assert.Equal(t, []event{{ID: 1, Msg: "a"}, {ID: 2, Msg: "b"}}, got)
}

func TestSubscribeBatch_OptionsPropagate(t *testing.T) {
	t.Run("defaults to one-per-call", func(t *testing.T) {
		f := &fakeClient{}
		bus.SubscribeBatch(f, bus.NewTopic[event]("t"), "g", func(context.Context, []event) []error { return nil })
		assert.Equal(t, 1, f.opts.BatchSize)
		assert.Equal(t, time.Duration(0), f.opts.Linger)
	})

	t.Run("batch size and linger flow through", func(t *testing.T) {
		f := &fakeClient{}
		bus.SubscribeBatch(f, bus.NewTopic[event]("t"), "g",
			func(context.Context, []event) []error { return nil },
			bus.WithBatchSize(10), bus.WithLinger(250*time.Millisecond))
		assert.Equal(t, 10, f.opts.BatchSize)
		assert.Equal(t, 250*time.Millisecond, f.opts.Linger)
	})
}

func TestWithBatchSize_IgnoresLessThanTwo(t *testing.T) {
	o := bus.SubscribeOptions{BatchSize: 1}
	bus.WithBatchSize(0)(&o)
	bus.WithBatchSize(1)(&o)
	assert.Equal(t, 1, o.BatchSize, "n<=1 must leave BatchSize untouched")

	bus.WithBatchSize(5)(&o)
	assert.Equal(t, 5, o.BatchSize)
}

func TestWithLinger_IgnoresNonPositive(t *testing.T) {
	o := bus.SubscribeOptions{}
	bus.WithLinger(0)(&o)
	bus.WithLinger(-time.Second)(&o)
	assert.Equal(t, time.Duration(0), o.Linger, "d<=0 must leave Linger untouched")

	bus.WithLinger(time.Second)(&o)
	assert.Equal(t, time.Second, o.Linger)
}

func TestWithConcurrency_IgnoresNonPositive(t *testing.T) {
	o := bus.SubscribeOptions{}
	bus.WithConcurrency(0)(&o)
	bus.WithConcurrency(-1)(&o)
	assert.Equal(t, 0, o.Concurrency, "n<=0 leaves the default (0 = unlimited)")

	bus.WithConcurrency(1)(&o)
	assert.Equal(t, 1, o.Concurrency, "n=1 is valid (serial)")

	bus.WithConcurrency(8)(&o)
	assert.Equal(t, 8, o.Concurrency)
}

func TestSubscribe_ConcurrencyOptionFlowsThrough(t *testing.T) {
	f := &fakeClient{}
	bus.Subscribe(f, bus.NewTopic[event]("t"), "g",
		func(context.Context, event) error { return nil },
		bus.WithConcurrency(10))
	assert.Equal(t, 1, f.opts.BatchSize, "Subscribe always forces one payload per call")
	assert.Equal(t, 10, f.opts.Concurrency)
}

func TestSubscribeBatch_ConcurrencyFlowsThrough(t *testing.T) {
	f := &fakeClient{}
	bus.SubscribeBatch(f, bus.NewTopic[event]("t"), "g",
		func(context.Context, []event) []error { return nil },
		bus.WithBatchSize(50), bus.WithConcurrency(10))
	assert.Equal(t, 50, f.opts.BatchSize)
	assert.Equal(t, 10, f.opts.Concurrency)
}
