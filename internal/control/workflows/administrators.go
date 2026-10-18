package workflows

import (
	"context"
	"errors"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

// AdministratorDirectory rechecks owner authority in the same SQL transaction as
// its read. It never exposes password hashes, handles or session authority.
type AdministratorDirectory interface {
	Administrators(context.Context, identity.AccountScope) ([]identity.AccountSummary, error)
}

type AccountAdministration struct{ directory AdministratorDirectory }

func NewAccountAdministration(directory AdministratorDirectory) *AccountAdministration {
	return &AccountAdministration{directory: directory}
}

func (s *AccountAdministration) Administrators(
	ctx context.Context,
	principal identity.Principal,
) ([]identity.AccountSummary, error) {
	if !principal.CanManageAccounts() || principal.AccountID != identity.OwnerAccountID ||
		principal.AuthVersion == 0 {
		return nil, identity.ErrInvalidCredential
	}
	if s.directory == nil {
		return nil, identity.ErrSecurityStateUnavailable
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	accounts, err := s.directory.Administrators(
		operation,
		identity.AccountScope{
			AccountID:   principal.AccountID,
			AuthVersion: principal.AuthVersion,
			Purpose:     principal.Purpose,
		},
	)
	if errors.Is(err, identity.ErrInvalidCredential) {
		return nil, identity.ErrInvalidCredential
	}
	if err != nil {
		return nil, identity.ErrSecurityStateUnavailable
	}

	return accounts, nil
}
