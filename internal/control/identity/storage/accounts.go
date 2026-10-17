package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) Account(ctx context.Context, id string) (identity.Account, error) {
	var account identity.Account
	err := s.pool.QueryRow(ctx, `SELECT account_id,COALESCE(email,''),role,status,auth_version,user_handle,COALESCE(password_hash,''),email_verified_at,created_at FROM admin_accounts WHERE account_id=$1`, id).
		Scan(&account.ID, &account.Email, &account.Role, &account.Status, &account.AuthVersion, &account.UserHandle, &account.PasswordHash, &account.EmailVerifiedAt, &account.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Account{}, identity.ErrInvalidCredential
	}
	if err != nil {
		return identity.Account{}, err
	}
	return account, nil
}

var _ identity.AccountReader = (*Repository)(nil)

func lockAccountScope(ctx context.Context, tx pgx.Tx, scope identity.AccountScope) error {
	var account identity.Account
	if err := tx.QueryRow(ctx, `SELECT account_id,role,status,auth_version FROM admin_accounts WHERE account_id=$1 FOR UPDATE`, scope.AccountID).
		Scan(&account.ID, &account.Role, &account.Status, &account.AuthVersion); errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return identity.ErrInvalidCredential
	} else if err != nil {
		return err
	}
	if !scope.Allows(account) {
		return identity.ErrInvalidCredential
	}
	return nil
}
