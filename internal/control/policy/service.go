package policy

import (
	"context"
	"sync"
)

type Store interface {
	Replace(context.Context, []Rule, Compiler) (Snapshot, error)
	Latest(context.Context) (Snapshot, error)
}
type Service struct {
	store    Store
	compiler Compiler
}

func NewService(store Store, compiler Compiler) *Service {
	return &Service{store: store, compiler: compiler}
}
func (s *Service) Replace(ctx context.Context, rules []Rule) (Snapshot, error) {
	return s.store.Replace(ctx, rules, s.compiler)
}
func (s *Service) Latest(ctx context.Context) (Snapshot, error) { return s.store.Latest(ctx) }

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
