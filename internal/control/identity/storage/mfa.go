package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) TOTP(ctx context.Context, accountID string) (identity.TOTPRecord, error) {
	var record identity.TOTPRecord
	var expires *time.Time

	err := s.pool.QueryRow(ctx, `SELECT totp_id::text,account_id,enrollment_auth_version,seed_ciphertext,created_at,pending_expires_at,confirmed_at,last_used_step FROM admin_totp WHERE account_id=$1`, accountID).
		Scan(&record.ID, &record.AccountID, &record.EnrollmentVersion, &record.Ciphertext, &record.CreatedAt, &expires, &record.ConfirmedAt, &record.LastStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.TOTPRecord{}, identity.ErrInvalidCredential
	}
	if err != nil {
		return identity.TOTPRecord{}, err
	}

	if expires != nil {
		record.ExpiresAt = *expires
	}

	return record, nil
}

func (s *Repository) SavePendingTOTP(
	ctx context.Context,
	scope identity.AccountScope,
	record identity.TOTPRecord,
) error {
	if (scope.Purpose != identity.SessionAdmin && scope.Purpose != identity.SessionEnrollment) ||
		record.AccountID != scope.AccountID ||
		record.EnrollmentVersion != scope.AuthVersion ||
		record.ConfirmedAt != nil ||
		record.LastStep != -1 {
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

	tag, err := tx.Exec(
		ctx,
		`INSERT INTO admin_totp(account_id,totp_id,enrollment_auth_version,seed_ciphertext,created_at,pending_expires_at,last_used_step)VALUES($1,$2,$3,$4,$5,$6,-1) ON CONFLICT(account_id)DO UPDATE SET totp_id=EXCLUDED.totp_id,enrollment_auth_version=EXCLUDED.enrollment_auth_version,seed_ciphertext=EXCLUDED.seed_ciphertext,created_at=EXCLUDED.created_at,pending_expires_at=EXCLUDED.pending_expires_at,last_used_step=-1 WHERE admin_totp.confirmed_at IS NULL`,
		scope.AccountID,
		record.ID,
		record.EnrollmentVersion,
		record.Ciphertext,
		record.CreatedAt,
		record.ExpiresAt,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return identity.ErrFactorExists
	}

	return tx.Commit(ctx)
}

func (s *Repository) ConfirmTOTP(
	ctx context.Context,
	scope identity.AccountScope,
	id string,
	step int64,
	now time.Time,
) error {
	if (scope.Purpose != identity.SessionAdmin && scope.Purpose != identity.SessionEnrollment) ||
		step < 0 {
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

	tag, err := tx.Exec(
		ctx,
		`UPDATE admin_totp SET confirmed_at=$5,pending_expires_at=NULL,last_used_step=$4 WHERE account_id=$1 AND totp_id=$2 AND enrollment_auth_version=$3 AND confirmed_at IS NULL AND created_at<=$5 AND pending_expires_at>$5 AND last_used_step<$4`,
		scope.AccountID,
		id,
		scope.AuthVersion,
		step,
		now,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return identity.ErrInvalidCredential
	}

	if err := completeMFAEnrollment(ctx, tx, scope); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Repository) ConsumeTOTP(
	ctx context.Context,
	scope identity.AccountScope,
	id string,
	step int64,
	_ time.Time,
) error {
	if scope.Purpose != identity.SessionAdmin || step < 0 {
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

	tag, err := tx.Exec(
		ctx,
		`UPDATE admin_totp SET last_used_step=$3 WHERE account_id=$1 AND totp_id=$2 AND confirmed_at IS NOT NULL AND last_used_step<$3`,
		scope.AccountID,
		id,
		step,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return identity.ErrInvalidCredential
	}

	return tx.Commit(ctx)
}

func (s *Repository) RemoveTOTP(ctx context.Context, scope identity.AccountScope) error {
	if scope.Purpose != identity.SessionAdmin {
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

	var configured bool

	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM admin_totp WHERE account_id=$1 AND confirmed_at IS NOT NULL)`, scope.AccountID).
		Scan(&configured); err != nil {
		return err
	}

	if !configured {
		return identity.ErrInvalidCredential
	}

	var alternate bool

	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_handle=(SELECT user_handle FROM admin_accounts WHERE account_id=$1))`, scope.AccountID).
		Scan(&alternate); err != nil {
		return err
	}

	if !alternate {
		return identity.ErrLastMFA
	}

	if _, err := tx.Exec(
		ctx,
		`DELETE FROM admin_totp WHERE account_id=$1`,
		scope.AccountID,
	); err != nil {
		return err
	}

	if err := advanceAuthVersion(ctx, tx, scope.AccountID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func advanceAuthVersion(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(
		ctx,
		`UPDATE admin_accounts SET auth_version=auth_version+1 WHERE account_id=$1`,
		id,
	)
	return err
}

var _ identity.MFARepository = (*Repository)(nil)

// First confirmed MFA and invited-account activation share the account lock and
// commit. Competing setup proofs are fenced by the epoch change.
func completeMFAEnrollment(ctx context.Context, tx pgx.Tx, scope identity.AccountScope) error {
	if scope.Purpose == identity.SessionAdmin {
		return advanceAuthVersion(ctx, tx, scope.AccountID)
	}
	if scope.Purpose != identity.SessionEnrollment {
		return identity.ErrInvalidCredential
	}

	tag, err := tx.Exec(
		ctx,
		`UPDATE admin_accounts SET status='active',auth_version=auth_version+1 WHERE account_id=$1 AND auth_version=$2 AND status='invited' AND role='admin' AND email_verified_at IS NOT NULL AND password_hash IS NOT NULL`,
		scope.AccountID,
		scope.AuthVersion,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return identity.ErrInvalidCredential
	}

	return nil
}
