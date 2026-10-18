package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) SaveMailToken(ctx context.Context, token identity.MailToken) error {
	if !token.Valid() {
		return identity.ErrInvalidCredential
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	account, err := readAccountRow(
		tx.QueryRow(ctx, accountProjection+` WHERE account_id=$1 FOR UPDATE`, token.AccountID),
	)
	if err != nil {
		return err
	}
	if !mailTokenAllows(token, account) {
		return identity.ErrInvalidCredential
	}

	var recent bool

	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM admin_mail_tokens WHERE account_id=$1 AND purpose=$2 AND created_at>$3)`, token.AccountID, token.Purpose, token.CreatedAt.Add(-time.Minute)).
		Scan(&recent); err != nil {
		return err
	}

	if recent {
		return identity.ErrMailRateLimited
	}

	if _, err := tx.Exec(
		ctx,
		`DELETE FROM admin_mail_tokens WHERE account_id=$1 AND purpose=$2`,
		token.AccountID,
		token.Purpose,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		ctx,
		`INSERT INTO admin_mail_tokens(token_hash,account_id,email,auth_version,purpose,created_at,expires_at)VALUES($1,$2,$3,$4,$5,$6,$7)`,
		token.Hash[:],
		token.AccountID,
		token.Email,
		token.AuthVersion,
		token.Purpose,
		token.CreatedAt,
		token.ExpiresAt,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func mailTokenAllows(token identity.MailToken, account identity.Account) bool {
	if token.AccountID != account.ID || token.Email != account.Email ||
		token.AuthVersion != account.AuthVersion {
		return false
	}

	switch token.Purpose {
	case identity.MailAdminInvitation:
		return account.Status == identity.AccountInvited && account.Role == identity.RoleAdmin
	case identity.MailEmailVerification:
		return account.Status == identity.AccountActive && account.EmailVerifiedAt == nil
	case identity.MailPasswordReset:
		return account.Status == identity.AccountActive && account.EmailVerifiedAt != nil
	default:
		return false
	}
}

func (s *Repository) ConsumeMailToken(
	ctx context.Context,
	use identity.MailTokenUse,
) (identity.Account, error) {
	if use.Hash == ([32]byte{}) || use.Now.IsZero() {
		return identity.Account{}, identity.ErrInvalidCredential
	}

	switch use.Purpose {
	case identity.MailAdminInvitation, identity.MailPasswordReset:
		if use.PasswordHash == "" || len(use.PasswordHash) > 512 {
			return identity.Account{}, identity.ErrInvalidCredential
		}
	case identity.MailEmailVerification:
		if use.PasswordHash != "" {
			return identity.Account{}, identity.ErrInvalidCredential
		}
	default:
		return identity.Account{}, identity.ErrInvalidCredential
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return identity.Account{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var accountID string

	err = tx.QueryRow(ctx, `SELECT account_id FROM admin_mail_tokens WHERE token_hash=$1`, use.Hash[:]).
		Scan(&accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Account{}, identity.ErrInvalidCredential
	}
	if err != nil {
		return identity.Account{}, err
	}

	// All token mutations lock account first and token second, including save and
	// concurrent redemption from independent replicas.
	account, err := readAccountRow(
		tx.QueryRow(ctx, accountProjection+` WHERE account_id=$1 FOR UPDATE`, accountID),
	)
	if err != nil {
		return identity.Account{}, err
	}

	var token identity.MailToken
	var usedAt *time.Time

	err = tx.QueryRow(ctx, `SELECT account_id,email,auth_version,purpose,created_at,expires_at,used_at FROM admin_mail_tokens WHERE token_hash=$1 FOR UPDATE`, use.Hash[:]).
		Scan(&token.AccountID, &token.Email, &token.AuthVersion, &token.Purpose, &token.CreatedAt, &token.ExpiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Account{}, identity.ErrInvalidCredential
	}
	if err != nil {
		return identity.Account{}, err
	}

	token.Hash = use.Hash
	if !token.Valid() || usedAt != nil || token.Purpose != use.Purpose ||
		use.Now.Before(token.CreatedAt) ||
		!use.Now.Before(token.ExpiresAt) ||
		!mailTokenAllows(token, account) {
		return identity.Account{}, identity.ErrInvalidCredential
	}

	switch use.Purpose {
	case identity.MailEmailVerification:
		_, err = tx.Exec(
			ctx,
			`UPDATE admin_accounts SET email_verified_at=$2 WHERE account_id=$1`,
			accountID,
			use.Now,
		)
	case identity.MailAdminInvitation:
		// Email possession plus a password is still not administrative authority.
		// Activation belongs to a separate password-bound MFA enrollment operation.
		_, err = tx.Exec(
			ctx,
			`UPDATE admin_accounts SET password_hash=$2,email_verified_at=$3,auth_version=auth_version+1 WHERE account_id=$1`,
			accountID,
			use.PasswordHash,
			use.Now,
		)
	case identity.MailPasswordReset:
		_, err = tx.Exec(
			ctx,
			`UPDATE admin_accounts SET password_hash=$2,auth_version=auth_version+1 WHERE account_id=$1`,
			accountID,
			use.PasswordHash,
		)
	}

	if err != nil {
		return identity.Account{}, err
	}

	if _, err = tx.Exec(
		ctx,
		`UPDATE admin_mail_tokens SET used_at=$2 WHERE token_hash=$1`,
		use.Hash[:],
		use.Now,
	); err != nil {
		return identity.Account{}, err
	}

	changed, err := readAccountRow(
		tx.QueryRow(ctx, accountProjection+` WHERE account_id=$1`, accountID),
	)
	if err != nil {
		return identity.Account{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return identity.Account{}, err
	}

	return changed, nil
}
