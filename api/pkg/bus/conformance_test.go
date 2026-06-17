package bus_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/rueidis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	busredis "github.com/thinkonmay/global-proxy/api/pkg/bus/redis"
)

// Conformance suite: shared cases run against every bus.Client. Backend-specific
// behaviour (redis redelivery, memory drop) gets its own tests below. Redis runs
// in a throwaway container from TestMain; skipped if Docker is unavailable.

// mirrors the unexported prefix in the redis backend.
const redisStreamPrefix = "bus:"

var (
	redisAddr string         // empty => redis backend skipped
	redisRaw  rueidis.Client // side channel used only to probe subscription readiness
	topicSeq  atomic.Uint64
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	ctx := context.Background()
	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		fmt.Fprintf(os.Stderr, "bus tests: redis container unavailable, skipping redis backend: %v\n", err)
		return m.Run()
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	endpoint, err := ctr.Endpoint(ctx, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "bus tests: redis endpoint: %v\n", err)
		return m.Run()
	}
	raw, err := rueidis.NewClient(rueidis.ClientOption{InitAddress: []string{endpoint}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bus tests: redis probe client: %v\n", err)
		return m.Run()
	}
	defer raw.Close()

	redisAddr = endpoint
	redisRaw = raw
	return m.Run()
}

// backend is one named implementation under test.
type backend struct {
	name string
	// newClient returns a fresh client, registering its shutdown on t.Cleanup.
	newClient func(t *testing.T) bus.Client
	// ready blocks until the subscription is live so Publish can't race it.
	ready func(t *testing.T, topic, group string, want int)
}

func backends() []backend {
	bs := []backend{{
		name: "memory",
		newClient: func(t *testing.T) bus.Client {
			m := busmemory.NewMemory(discardLogger())
			t.Cleanup(func() { _ = m.Close() })
			return m
		},
		// memory subscribes synchronously; nothing to wait for.
		ready: func(*testing.T, string, string, int) {},
	}}

	if redisAddr != "" {
		bs = append(bs, backend{
			name: "redis",
			newClient: func(t *testing.T) bus.Client {
				r, err := busredis.Connect([]string{redisAddr}, discardLogger())
				require.NoError(t, err)
				t.Cleanup(func() { _ = r.Close() })
				return r
			},
			ready: redisReady,
		})
	}
	return bs
}

func forEachBackend(t *testing.T, fn func(t *testing.T, b backend)) {
	for _, b := range backends() {
		t.Run(b.name, func(t *testing.T) { fn(t, b) })
	}
}

// redisReady polls XINFO GROUPS until the group has >= want consumers (each
// appears after its first XREADGROUP, i.e. its read loop is live).
func redisReady(t *testing.T, topic, group string, want int) {
	t.Helper()
	stream := redisStreamPrefix + topic
	ctx := context.Background()
	for range 200 { // ~10s
		arr, err := redisRaw.Do(ctx, redisRaw.B().XinfoGroups().Key(stream).Build()).ToArray()
		if err == nil {
			for _, g := range arr {
				mp, err := g.AsMap()
				if err != nil {
					continue
				}
				nameMsg, consMsg := mp["name"], mp["consumers"]
				name, _ := nameMsg.ToString()
				if name != group {
					continue
				}
				if n, _ := consMsg.ToInt64(); int(n) >= want {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("redis group %q on stream %q not ready (want %d consumers)", group, stream, want)
}

func uniqueTopic(t *testing.T) string {
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	return fmt.Sprintf("test.%s.%d", name, topicSeq.Add(1))
}

// sink records each handler batch on a channel for timeout-based assertions,
// avoiding any backend-specific Wait.
type sink struct {
	batches chan []event
}

func newSink() *sink { return &sink{batches: make(chan []event, 4096)} }

func (s *sink) handle(_ context.Context, payloads []event) error {
	s.batches <- append([]event(nil), payloads...)
	return nil
}

func (s *sink) handleOne(_ context.Context, e event) error {
	s.batches <- []event{e}
	return nil
}

// collect drains batches until n events have arrived, then returns them flat.
func (s *sink) collect(t *testing.T, n int, timeout time.Duration) []event {
	t.Helper()
	got := make([]event, 0, n)
	deadline := time.After(timeout)
	for len(got) < n {
		select {
		case b := <-s.batches:
			got = append(got, b...)
		case <-deadline:
			t.Fatalf("timed out waiting for events: got %d/%d", len(got), n)
		}
	}
	return got
}

// collectBatches drains until n events have arrived, returning the batch
// boundaries so a test can assert on how payloads were grouped.
func (s *sink) collectBatches(t *testing.T, n int, timeout time.Duration) [][]event {
	t.Helper()
	var batches [][]event
	count := 0
	deadline := time.After(timeout)
	for count < n {
		select {
		case b := <-s.batches:
			batches = append(batches, b)
			count += len(b)
		case <-deadline:
			t.Fatalf("timed out waiting for batches: got %d/%d events", count, n)
		}
	}
	return batches
}

// expectNoMore fails if any further batch arrives within grace.
func (s *sink) expectNoMore(t *testing.T, grace time.Duration) {
	t.Helper()
	select {
	case extra := <-s.batches:
		t.Fatalf("unexpected extra delivery: %v", extra)
	case <-time.After(grace):
	}
}

func publishRange(t *testing.T, c bus.Client, topic bus.Topic[event], from, to int) {
	t.Helper()
	for i := from; i <= to; i++ {
		require.NoError(t, bus.Publish(context.Background(), c, topic, event{ID: i, Msg: fmt.Sprintf("m%d", i)}))
	}
}

// --- conformance cases (run against every backend) ---

func TestConformance_DeliversPayload(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.newClient(t)
		topic := bus.NewTopic[event](uniqueTopic(t))
		s := newSink()

		bus.Subscribe(c, topic, "g1", s.handleOne)
		b.ready(t, topic.Name, "g1", 1)
		require.NoError(t, bus.Publish(context.Background(), c, topic, event{ID: 1, Msg: "hi"}))

		got := s.collect(t, 1, 5*time.Second)
		assert.Equal(t, event{ID: 1, Msg: "hi"}, got[0])
	})
}

func TestConformance_FanOutAcrossGroups(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.newClient(t)
		topic := bus.NewTopic[event](uniqueTopic(t))
		s := newSink()

		bus.Subscribe(c, topic, "groupA", s.handleOne)
		bus.Subscribe(c, topic, "groupB", s.handleOne)
		b.ready(t, topic.Name, "groupA", 1)
		b.ready(t, topic.Name, "groupB", 1)

		const n = 5
		publishRange(t, c, topic, 1, n)

		// Every group gets a full copy => 2*n total, each id seen exactly twice.
		got := s.collect(t, 2*n, 5*time.Second)
		counts := map[int]int{}
		for _, e := range got {
			counts[e.ID]++
		}
		for id := 1; id <= n; id++ {
			assert.Equal(t, 2, counts[id], "id %d should be delivered once per group", id)
		}
	})
}

func TestConformance_CompetingConsumersSameGroup(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.newClient(t)
		topic := bus.NewTopic[event](uniqueTopic(t))
		s := newSink() // shared by both consumers in the group

		bus.Subscribe(c, topic, "workers", s.handleOne)
		bus.Subscribe(c, topic, "workers", s.handleOne)
		b.ready(t, topic.Name, "workers", 2)

		const n = 20
		publishRange(t, c, topic, 1, n)

		// Competing consumers split the work: each id delivered exactly once
		// across the group (happy path, no handler errors => no redelivery).
		got := s.collect(t, n, 5*time.Second)
		seen := map[int]int{}
		for _, e := range got {
			seen[e.ID]++
		}
		assert.Len(t, seen, n, "every id should appear exactly once")
		for id := 1; id <= n; id++ {
			assert.Equal(t, 1, seen[id], "id %d delivered once", id)
		}
		s.expectNoMore(t, 300*time.Millisecond)
	})
}

func TestConformance_PreservesOrderWithinGroup(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.newClient(t)
		topic := bus.NewTopic[event](uniqueTopic(t))
		s := newSink()

		bus.Subscribe(c, topic, "g1", s.handleOne)
		b.ready(t, topic.Name, "g1", 1)

		const n = 50
		publishRange(t, c, topic, 1, n)

		got := s.collect(t, n, 5*time.Second)
		ids := make([]int, len(got))
		for i, e := range got {
			ids[i] = e.ID
		}
		want := make([]int, n)
		for i := range want {
			want[i] = i + 1
		}
		assert.True(t, sort.IntsAreSorted(ids), "single-consumer delivery must stay FIFO")
		assert.Equal(t, want, ids)
	})
}

func TestConformance_BatchesPayloads(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.newClient(t)
		topic := bus.NewTopic[event](uniqueTopic(t))
		s := newSink()

		const n = 20
		bus.SubscribeBatch(c, topic, "g1", s.handle, bus.WithBatchSize(n), bus.WithLinger(time.Second))
		b.ready(t, topic.Name, "g1", 1)

		publishRange(t, c, topic, 1, n)

		batches := s.collectBatches(t, n, 5*time.Second)
		maxBatch := 0
		total := 0
		for _, batch := range batches {
			total += len(batch)
			assert.LessOrEqual(t, len(batch), n, "batch must not exceed BatchSize")
			if len(batch) > maxBatch {
				maxBatch = len(batch)
			}
		}
		assert.Equal(t, n, total, "all payloads delivered")
		assert.Greater(t, maxBatch, 1, "at least one batch should hold multiple payloads")
	})
}

func TestConformance_PingHealthy(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.newClient(t)
		assert.NoError(t, c.Ping())
	})
}

func TestConformance_PublishAfterCloseFails(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.newClient(t)
		topic := bus.NewTopic[event](uniqueTopic(t))
		require.NoError(t, c.Close())

		err := bus.Publish(context.Background(), c, topic, event{ID: 1})
		assert.Error(t, err, "publishing after Close must fail")
	})
}

// --- memory-specific behaviour ---

func TestMemory_WaitBlocksUntilHandled(t *testing.T) {
	m := busmemory.NewMemory(discardLogger())
	t.Cleanup(func() { _ = m.Close() })
	topic := bus.NewTopic[event](uniqueTopic(t))

	var handled atomic.Int64
	bus.Subscribe(m, topic, "g1", func(_ context.Context, _ event) error {
		time.Sleep(20 * time.Millisecond) // make the race observable
		handled.Add(1)
		return nil
	})

	const n = 10
	publishRange(t, m, topic, 1, n)
	m.Wait() // contract: returns only once every published payload was handled
	assert.Equal(t, int64(n), handled.Load())
}

func TestMemory_HandlerErrorIsDroppedNotRedelivered(t *testing.T) {
	m := busmemory.NewMemory(discardLogger())
	t.Cleanup(func() { _ = m.Close() })
	topic := bus.NewTopic[event](uniqueTopic(t))

	var calls atomic.Int64
	bus.Subscribe(m, topic, "g1", func(context.Context, event) error {
		calls.Add(1)
		return fmt.Errorf("boom")
	})

	require.NoError(t, bus.Publish(context.Background(), m, topic, event{ID: 1}))
	m.Wait() // inflight must drain even though the handler errored

	// At-most-once: a failed handler does not get the payload again.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int64(1), calls.Load())
}

func TestMemory_PublishAfterCloseReturnsErrClosed(t *testing.T) {
	m := busmemory.NewMemory(discardLogger())
	require.NoError(t, m.Close())
	err := bus.Publish(context.Background(), m, bus.NewTopic[event]("t"), event{ID: 1})
	assert.ErrorIs(t, err, busmemory.ErrClosed)
}

// --- redis-specific behaviour ---

func TestRedis_RedeliversUnackedAfterRestart(t *testing.T) {
	if redisAddr == "" {
		t.Skip("redis backend unavailable")
	}
	topic := bus.NewTopic[event](uniqueTopic(t))

	// first client errors on every payload => nothing acked, entry stays pending.
	r1, err := busredis.Connect([]string{redisAddr}, discardLogger())
	require.NoError(t, err)
	var firstCalls atomic.Int64
	bus.Subscribe(r1, topic, "g1", func(context.Context, event) error {
		firstCalls.Add(1)
		return fmt.Errorf("boom")
	})
	redisReady(t, topic.Name, "g1", 1)
	require.NoError(t, bus.Publish(context.Background(), r1, topic, event{ID: 99, Msg: "keep"}))

	require.Eventually(t, func() bool { return firstCalls.Load() >= 1 }, 5*time.Second, 20*time.Millisecond)
	require.NoError(t, r1.Close())

	// second client, same group: replays the pending entry via the "0" backlog pass.
	r2, err := busredis.Connect([]string{redisAddr}, discardLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = r2.Close() })
	s := newSink()
	bus.Subscribe(r2, topic, "g1", s.handleOne)

	got := s.collect(t, 1, 5*time.Second)
	assert.Equal(t, event{ID: 99, Msg: "keep"}, got[0])
}

// --- concurrency / stress ---

// many publishers fan into a multi-consumer group; every id must arrive at
// least once (memory at-most-once delivers all via backpressure, redis
// at-least-once). Run with -race to validate the backends under contention.
func TestStress_ConcurrentPublishers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in -short")
	}
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.newClient(t)
		topic := bus.NewTopic[event](uniqueTopic(t))
		s := newSink()

		const consumers = 4
		for range consumers {
			bus.Subscribe(c, topic, "workers", s.handleOne)
		}
		b.ready(t, topic.Name, "workers", consumers)

		const publishers, perPub = 8, 250
		total := publishers * perPub

		var wg sync.WaitGroup
		for p := range publishers {
			wg.Go(func() {
				base := p * perPub
				for i := 1; i <= perPub; i++ {
					require.NoError(t, bus.Publish(context.Background(), c, topic, event{ID: base + i}))
				}
			})
		}
		wg.Wait()

		seen := make(map[int]bool, total)
		deadline := time.After(20 * time.Second)
		for len(seen) < total {
			select {
			case batch := <-s.batches:
				for _, e := range batch {
					seen[e.ID] = true
				}
			case <-deadline:
				t.Fatalf("stress: saw %d/%d unique ids", len(seen), total)
			}
		}
	})
}

// Publish racing Close exercises memory's lock discipline (send under RLock,
// Close under Lock). -race must report clean; no send-on-closed-channel panic.
func TestRace_PublishDuringClose(t *testing.T) {
	m := busmemory.NewMemory(discardLogger())
	topic := bus.NewTopic[event](uniqueTopic(t))
	bus.Subscribe(m, topic, "g1", func(context.Context, event) error { return nil })

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for i := range 2000 {
				// ErrClosed after Close is expected; just must not race or panic.
				_ = bus.Publish(context.Background(), m, topic, event{ID: i})
			}
		})
	}
	go func() { _ = m.Close() }()
	wg.Wait()
}
