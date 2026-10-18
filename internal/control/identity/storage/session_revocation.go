package storage

import (
	"context"
	"math"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) RevokeSessions(ctx context.Context, scope identity.AccountScope) error {
	if scope.Purpose != identity.SessionAdmin {
		return identity.ErrInvalidCredential
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()

		_ = tx.Rollback(cleanup)
	}()

	account, err := lockedAccountScope(ctx, tx, scope)
	if err != nil {
		return err
	}
	if account.AuthVersion >= math.MaxInt64 {
		return identity.ErrInvalidCredential
	}

	changed, err := tx.Exec(
		ctx,
		`UPDATE admin_accounts SET auth_version=auth_version+1 WHERE account_id=$1`,
		scope.AccountID,
	)
	if err != nil {
		return err
	}
	if changed.RowsAffected() != 1 {
		return identity.ErrInvalidCredential
	}

	if _, err := tx.Exec(
		ctx,
		`DELETE FROM admin_mail_tokens WHERE account_id=$1`,
		scope.AccountID,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
