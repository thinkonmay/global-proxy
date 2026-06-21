package idempotency

import (
	"context"
	"sync"
	"time"
)

const inFlightWindow = 2 * time.Minute

var _ Store = (*MemStore)(nil)

// MemStore is an in-process ledger (tests, single-node).
type MemStore struct {
	mu      sync.Mutex
	status  map[string]string
	updated map[string]time.Time
}

func NewMemStore() *MemStore {
	return &MemStore{
		status:  make(map[string]string),
		updated: make(map[string]time.Time),
	}
}

func (s *MemStore) Register(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, seen := s.status[id]
	if !seen {
		s.status[id] = "pending"
		s.updated[id] = time.Now()
		return true, nil
	}
	if st == "done" {
		return false, nil
	}
	if st == "pending" && time.Since(s.updated[id]) < inFlightWindow {
		return false, nil
	}
	s.status[id] = "pending"
	s.updated[id] = time.Now()
	return true, nil
}

func (s *MemStore) MarkDone(_ context.Context, id string) error {
	s.mu.Lock()
	s.status[id] = "done"
	s.updated[id] = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *MemStore) MarkError(_ context.Context, id string) error {
	s.mu.Lock()
	s.status[id] = "error"
	s.updated[id] = time.Now()
	s.mu.Unlock()
	return nil
}
