package idempotency

import (
	"context"
	"sync"
)

var _ Store = (*MemStore)(nil)

// MemStore is an in-process ledger (tests, single-node).
type MemStore struct {
	mu     sync.Mutex
	status map[string]string
}

func NewMemStore() *MemStore { return &MemStore{status: make(map[string]string)} }

func (s *MemStore) Register(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.status[id]; seen {
		return false, nil // already attempted -> skip
	}
	s.status[id] = "pending"
	return true, nil
}

func (s *MemStore) MarkDone(_ context.Context, id string) error {
	s.mu.Lock()
	s.status[id] = "done"
	s.mu.Unlock()
	return nil
}

func (s *MemStore) MarkError(_ context.Context, id string) error {
	s.mu.Lock()
	s.status[id] = "error"
	s.mu.Unlock()
	return nil
}
