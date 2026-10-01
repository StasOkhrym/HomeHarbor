package policy

import (
	"context"
	"errors"
)

// ErrRevisionConflict means a reviewed policy was superseded before commit.
var ErrRevisionConflict = errors.New("policy revision changed")

type Repository interface {
	Replace(context.Context, []Rule, Compiler) (Snapshot, error)
	ReplaceIfRevision(context.Context, uint64, []Rule, Compiler) (Snapshot, error)
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

// ReplaceIfRevision commits a reviewed change only against its exact base.
// The repository checks and writes under the same lock/transaction.
func (s *Service) ReplaceIfRevision(
	ctx context.Context,
	revision uint64,
	rules []Rule,
) (Snapshot, error) {
	return s.store.ReplaceIfRevision(ctx, revision, rules, s.compiler)
}
