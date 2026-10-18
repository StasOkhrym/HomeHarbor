package storage

import (
	"bytes"
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) PrepareAdminInvitation(
	ctx context.Context,
	owner identity.AccountScope,
	candidate identity.Account,
) error {
	email, err := identity.CanonicalEmail(candidate.Email)
	if err != nil || email != candidate.Email || candidate.ID == "" || len(candidate.ID) > 128 ||
		candidate.ID == identity.OwnerAccountID ||
		candidate.Role != identity.RoleAdmin ||
		candidate.Status != identity.AccountInvited ||
		candidate.PasswordHash != "" ||
		candidate.EmailVerifiedAt != nil ||
		candidate.CreatedAt.IsZero() ||
		len(candidate.UserHandle) < 1 ||
		len(candidate.UserHandle) > 64 {
		return identity.ErrInvalidCredential
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockOwner(ctx, tx, owner); err != nil {
		return err
	}

	current, err := readAccountRow(
		tx.QueryRow(ctx, accountProjection+` WHERE account_id=$1 FOR UPDATE`, candidate.ID),
	)
	if errors.Is(err, identity.ErrInvalidCredential) {
		if candidate.AuthVersion != 1 {
			return identity.ErrInvalidCredential
		}

		_, err = tx.Exec(
			ctx,
			`INSERT INTO admin_accounts(account_id,email,role,status,auth_version,user_handle,created_at)VALUES($1,$2,'admin','invited',1,$3,$4)`,
			candidate.ID,
			candidate.Email,
			candidate.UserHandle,
			candidate.CreatedAt,
		)
	} else if err == nil {
		if current.Role != identity.RoleAdmin || current.Status != identity.AccountInvited ||
			current.Email != candidate.Email ||
			candidate.AuthVersion != current.AuthVersion+1 ||
			!bytes.Equal(current.UserHandle, candidate.UserHandle) ||
			!current.CreatedAt.Equal(candidate.CreatedAt) {
			return identity.ErrInvitationConflict
		}

		_, err = tx.Exec(
			ctx,
			`UPDATE admin_accounts SET auth_version=auth_version+1,password_hash=NULL,email_verified_at=NULL WHERE account_id=$1`,
			candidate.ID,
		)
	}

	if err != nil {
		var conflict *pgconn.PgError
		if errors.As(err, &conflict) && conflict.Code == "23505" {
			return identity.ErrInvitationConflict
		}

		return err
	}

	return tx.Commit(ctx)
}

// OwnerForUpdate participates only in an explicitly bound caller transaction.
// The retained account lock serializes owner actions across control replicas.
func (s *Repository) OwnerForUpdate(
	ctx context.Context,
	scope identity.AccountScope,
) (identity.Account, error) {
	tx, ok := s.pool.(pgx.Tx)
	if !ok {
		return identity.Account{}, identity.ErrSecurityStateUnavailable
	}

	return lockedOwner(ctx, tx, scope)
}

func lockOwner(ctx context.Context, tx pgx.Tx, scope identity.AccountScope) error {
	_, err := lockedOwner(ctx, tx, scope)
	return err
}

func lockedOwner(
	ctx context.Context,
	tx pgx.Tx,
	scope identity.AccountScope,
) (identity.Account, error) {
	if scope.AccountID != identity.OwnerAccountID || scope.Purpose != identity.SessionAdmin {
		return identity.Account{}, identity.ErrInvalidCredential
	}

	account, err := lockedAccountScope(ctx, tx, scope)
	if err != nil {
		return identity.Account{}, err
	}
	if account.Role != identity.RoleOwner {
		return identity.Account{}, identity.ErrInvalidCredential
	}

	return account, nil
}

func (s *Repository) RevokeAdmin(
	ctx context.Context,
	owner identity.AccountScope,
	accountID string,
) error {
	if accountID == "" || accountID == identity.OwnerAccountID {
		return identity.ErrInvalidCredential
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockOwner(ctx, tx, owner); err != nil {
		return err
	}

	account, err := readAccountRow(
		tx.QueryRow(ctx, accountProjection+` WHERE account_id=$1 FOR UPDATE`, accountID),
	)
	if err != nil {
		return err
	}
	if account.Role != identity.RoleAdmin {
		return identity.ErrInvalidCredential
	}
	if account.Status == identity.AccountRevoked {
		return nil
	}

	if _, err := tx.Exec(
		ctx,
		`UPDATE admin_accounts SET status='revoked',auth_version=auth_version+1 WHERE account_id=$1`,
		accountID,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		ctx,
		`DELETE FROM admin_mail_tokens WHERE account_id=$1`,
		accountID,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
