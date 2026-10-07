package policy

import (
	"context"
	"sync"

	"github.com/StasOkhrym/homeharbor/internal/acl"
)

// MemoryStore is an in-process test double for Repository.
type MemoryStore struct {
	mu     sync.Mutex
	latest acl.Snapshot
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (s *MemoryStore) Replace(
	_ context.Context,
	rules []acl.Rule,
	compiler acl.Compiler,
) (acl.Snapshot, error) {
	return s.replace(rules, compiler, nil)
}

func (s *MemoryStore) ReplaceIfRevision(
	_ context.Context,
	revision uint64,
	rules []acl.Rule,
	compiler acl.Compiler,
) (acl.Snapshot, error) {
	return s.replace(rules, compiler, &revision)
}

func (s *MemoryStore) replace(
	rules []acl.Rule,
	compiler acl.Compiler,
	expected *uint64,
) (acl.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != nil && s.latest.Revision != *expected {
		return acl.Snapshot{}, ErrRevisionConflict
	}
	snapshot, err := compiler.Compile(s.latest.Revision+1, rules)
	if err != nil {
		return acl.Snapshot{}, err
	}
	s.latest = snapshot
	return snapshot, nil
}

func (s *MemoryStore) Latest(_ context.Context) (acl.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest, nil
}

var _ Repository = (*MemoryStore)(nil)
