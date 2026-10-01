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
	return s.replace(rules, compiler, nil)
}

func (s *MemoryStore) ReplaceIfRevision(
	_ context.Context,
	revision uint64,
	rules []Rule,
	compiler Compiler,
) (Snapshot, error) {
	return s.replace(rules, compiler, &revision)
}

func (s *MemoryStore) replace(rules []Rule, compiler Compiler, expected *uint64) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != nil && s.latest.Revision != *expected {
		return Snapshot{}, ErrRevisionConflict
	}
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
