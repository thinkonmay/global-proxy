// Package cachememory is an in-process cache.Client backed by a map with TTL
// expiry and a background sweep.
package cachememory

import (
	"context"
	"sync"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/cache"
)

const sweepInterval = 5 * time.Minute

var _ cache.Client = (*Memory)(nil)

type entry struct {
	value  []byte
	expiry time.Time // zero = no expiry
}

func (e entry) expired() bool {
	return !e.expiry.IsZero() && time.Now().After(e.expiry)
}

// Memory caches byte values in a map, evicting them when their TTL lapses.
type Memory struct {
	mu    sync.RWMutex
	items map[string]entry

	ticker    *time.Ticker
	stop      chan struct{}
	closeOnce sync.Once
}

// New starts an in-memory cache with a background sweep of expired keys.
func New() *Memory {
	m := &Memory{
		items:  make(map[string]entry),
		ticker: time.NewTicker(sweepInterval),
		stop:   make(chan struct{}),
	}
	go m.sweep()
	return m
}

func (m *Memory) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	e, ok := m.items[key]
	m.mu.RUnlock()
	if !ok || e.expired() {
		return nil, cache.ErrMiss
	}
	return e.value, nil
}

func (m *Memory) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e := entry{value: value}
	if ttl > 0 {
		e.expiry = time.Now().Add(ttl)
	}
	m.mu.Lock()
	m.items[key] = e
	m.mu.Unlock()
	return nil
}

func (m *Memory) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.items, key)
	m.mu.Unlock()
	return nil
}

func (m *Memory) Ping() error { return nil }

// Close stops the sweep goroutine. Safe to call more than once.
func (m *Memory) Close() error {
	m.closeOnce.Do(func() {
		m.ticker.Stop()
		close(m.stop)
	})
	return nil
}

func (m *Memory) sweep() {
	for {
		select {
		case <-m.ticker.C:
			m.mu.Lock()
			for key, e := range m.items {
				if e.expired() {
					delete(m.items, key)
				}
			}
			m.mu.Unlock()
		case <-m.stop:
			return
		}
	}
}
