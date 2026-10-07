package policy

import (
	"context"
	"slices"
	"sync"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/policy"
)

// Repository is an in-process test double for policy.Repository.
type Repository struct {
	mu     sync.Mutex
	latest acl.Snapshot
}

func NewRepository() *Repository {
	return &Repository{latest: acl.Snapshot{DefaultAction: acl.ActionDeny, Rules: []acl.Rule{}}}
}

func (s *Repository) Replace(
	ctx context.Context,
	rules []acl.Rule,
	compiler acl.Compiler,
) (acl.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		var zero acl.Snapshot
		return zero, err
	}

	return s.replace(ctx, rules, compiler, nil)
}

func (s *Repository) ReplaceIfRevision(
	ctx context.Context,
	revision uint64,
	rules []acl.Rule,
	compiler acl.Compiler,
) (acl.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		var zero acl.Snapshot
		return zero, err
	}

	return s.replace(ctx, rules, compiler, &revision)
}

func (s *Repository) replace(
	ctx context.Context,
	rules []acl.Rule,
	compiler acl.Compiler,
	expected *uint64,
) (acl.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return acl.Snapshot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if expected != nil && s.latest.Revision != *expected {
		return acl.Snapshot{}, domainpkg.ErrRevisionConflict
	}

	snapshot, err := compiler.Compile(s.latest.Revision+1, rules)
	if err != nil {
		return acl.Snapshot{}, err
	}

	s.latest = cloneSnapshot(snapshot)

	return cloneSnapshot(snapshot), nil
}

func (s *Repository) Latest(ctx context.Context) (acl.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return acl.Snapshot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return cloneSnapshot(s.latest), nil
}

func cloneSnapshot(snapshot acl.Snapshot) acl.Snapshot {
	snapshot.Rules = slices.Clone(snapshot.Rules)
	return snapshot
}

var _ domainpkg.Repository = (*Repository)(nil)
