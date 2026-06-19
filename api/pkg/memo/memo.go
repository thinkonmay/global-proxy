// Package memo is a generic memoizer: it lazily builds one value per key and
// evicts the least-recently-used entry once it is full. For live in-process
// values (rate limiters, breakers), not serialized data.
package memo

import (
	"container/list"
	"sync"
)

// Cache lazily builds one value per key and caches it, evicting the
// least-recently-used entry once the count exceeds capacity (capacity <= 0 =
// unbounded). Safe for concurrent use.
type Cache[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	build    func(K) V
	order    *list.List // front = most recently used
	items    map[K]*list.Element
}

type entry[K comparable, V any] struct {
	key K
	val V
}

func New[K comparable, V any](capacity int, build func(K) V) *Cache[K, V] {
	return &Cache[K, V]{
		capacity: capacity,
		build:    build,
		order:    list.New(),
		items:    make(map[K]*list.Element),
	}
}

// Get returns the cached value for key, building and caching it on first use.
func (c *Cache[K, V]) Get(key K) V {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*entry[K, V]).val
	}
	v := c.build(key)
	c.items[key] = c.order.PushFront(&entry[K, V]{key, v})
	if c.capacity > 0 && c.order.Len() > c.capacity {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*entry[K, V]).key)
	}
	return v
}

// Len reports the number of cached entries.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
