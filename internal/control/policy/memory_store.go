package policy

import (
	"context"
	"sync"
)

// MemoryStore is an in-process test double for Repository.
type MemoryStore struct {
	mu     sync.Mutex
	latest Snapshot
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }
func (s *MemoryStore) Replace(_ context.Context, rules []Rule, compiler Compiler) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := compiler.Compile(s.latest.Revision+1, rules)
	if err != nil {
		return Snapshot{}, err
	}
	s.latest = snapshot
	return snapshot, nil
}

func (s *MemoryStore) Latest(_ context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest, nil
}

var _ Repository = (*MemoryStore)(nil)
