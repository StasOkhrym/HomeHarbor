package policy

import (
	"context"
	"errors"

	"github.com/StasOkhrym/homeharbor/internal/acl"
)

// ErrRevisionConflict means a reviewed policy was superseded before commit.
var ErrRevisionConflict = errors.New("policy revision changed")

type Repository interface {
	Replace(context.Context, []acl.Rule, acl.Compiler) (acl.Snapshot, error)
	ReplaceIfRevision(context.Context, uint64, []acl.Rule, acl.Compiler) (acl.Snapshot, error)
	Latest(context.Context) (acl.Snapshot, error)
}
type Service struct {
	store    Repository
	compiler acl.Compiler
}

func NewService(store Repository, compiler acl.Compiler) *Service {
	return &Service{store: store, compiler: compiler}
}

func (s *Service) Replace(ctx context.Context, rules []acl.Rule) (acl.Snapshot, error) {
	return s.store.Replace(ctx, rules, s.compiler)
}
func (s *Service) Latest(ctx context.Context) (acl.Snapshot, error) { return s.store.Latest(ctx) }

// ReplaceIfRevision commits a reviewed change only against its exact base.
// The repository checks and writes under the same lock/transaction.
func (s *Service) ReplaceIfRevision(
	ctx context.Context,
	revision uint64,
	rules []acl.Rule,
) (acl.Snapshot, error) {
	return s.store.ReplaceIfRevision(ctx, revision, rules, s.compiler)
}
