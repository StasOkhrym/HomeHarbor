package policy

import (
	"context"
)

type Repository interface {
	Replace(context.Context, []Rule, Compiler) (Snapshot, error)
	Latest(context.Context) (Snapshot, error)
}
type Service struct {
	store    Repository
	compiler Compiler
}

func NewService(store Repository, compiler Compiler) *Service {
	return &Service{store: store, compiler: compiler}
}

func (s *Service) Replace(ctx context.Context, rules []Rule) (Snapshot, error) {
	return s.store.Replace(ctx, rules, s.compiler)
}
func (s *Service) Latest(ctx context.Context) (Snapshot, error) { return s.store.Latest(ctx) }
