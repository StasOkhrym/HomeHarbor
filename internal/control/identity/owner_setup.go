package identity

import (
	"context"
	"time"
)

func (s *LoginService) ConfigureOwner(
	ctx context.Context,
	principal Principal,
	email, password string,
) error {
	now := s.now().UTC()
	if principal.AccountID != OwnerAccountID || principal.Role != RoleOwner ||
		principal.Purpose != SessionMigration ||
		principal.AuthVersion == 0 ||
		principal.AuthenticatedAt.IsZero() ||
		now.Before(principal.AuthenticatedAt) ||
		now.Sub(principal.AuthenticatedAt) >= 5*time.Minute ||
		(principal.Method != "passkey" && principal.Method != "recovery") {
		return ErrInvalidCredential
	}

	canonical, err := CanonicalEmail(email)
	if err != nil {
		return ErrInvalidCredential
	}

	account, err := readAccount(ctx, s.accounts, principal.AccountID)
	if err != nil {
		return err
	}

	scope := AccountScope{
		AccountID:   principal.AccountID,
		AuthVersion: principal.AuthVersion,
		Purpose:     SessionMigration,
	}
	if !scope.Allows(account) {
		return ErrInvalidCredential
	}

	hash, err := s.passwords.Hash(ctx, password)
	if err != nil {
		return err
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return securityStoreError(s.accounts.ConfigureOwner(operation, scope, canonical, hash))
}
