package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) Account(ctx context.Context, id string) (identity.Account, error) {
	return readAccountRow(s.pool.QueryRow(ctx, accountProjection+` WHERE account_id=$1`, id))
}

func (s *Repository) AccountByEmail(ctx context.Context, email string) (identity.Account, error) {
	return readAccountRow(s.pool.QueryRow(ctx, accountProjection+` WHERE email=$1`, email))
}

const accountProjection = `SELECT account_id,COALESCE(email,''),role,status,auth_version,user_handle,COALESCE(password_hash,''),email_verified_at,created_at FROM admin_accounts`

func readAccountRow(row pgx.Row) (identity.Account, error) {
	var account identity.Account

	err := row.Scan(
		&account.ID,
		&account.Email,
		&account.Role,
		&account.Status,
		&account.AuthVersion,
		&account.UserHandle,
		&account.PasswordHash,
		&account.EmailVerifiedAt,
		&account.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Account{}, identity.ErrInvalidCredential
	}
	if err != nil {
		return identity.Account{}, err
	}

	return account, nil
}

func (s *Repository) ConfigureOwner(
	ctx context.Context,
	scope identity.AccountScope,
	email, hash string,
) error {
	if scope.Purpose != identity.SessionMigration {
		return identity.ErrInvalidCredential
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockAccountScope(ctx, tx, scope); err != nil {
		return err
	}

	if _, err := tx.Exec(
		ctx,
		`UPDATE admin_accounts SET email=$2,password_hash=$3,status='active',auth_version=auth_version+1 WHERE account_id=$1`,
		scope.AccountID,
		email,
		hash,
	); err != nil {
		var conflict *pgconn.PgError
		if errors.As(err, &conflict) && conflict.Code == "23505" {
			return identity.ErrInvalidCredential
		}

		return err
	}

	return tx.Commit(ctx)
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
