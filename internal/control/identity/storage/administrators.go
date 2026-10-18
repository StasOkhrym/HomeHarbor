package storage

import (
	"context"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) Administrators(
	ctx context.Context,
	owner identity.AccountScope,
) ([]identity.AccountSummary, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()

		_ = tx.Rollback(cleanup)
	}()

	if err := lockOwner(ctx, tx, owner); err != nil {
		return nil, err
	}

	rows, err := tx.Query(
		ctx,
		`SELECT account_id,COALESCE(email,''),role,status,email_verified_at IS NOT NULL,created_at FROM admin_accounts ORDER BY (role='owner') DESC,email,account_id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := make([]identity.AccountSummary, 0)
	for rows.Next() {
		var account identity.AccountSummary

		if err := rows.Scan(
			&account.ID,
			&account.Email,
			&account.Role,
			&account.Status,
			&account.EmailVerified,
			&account.CreatedAt,
		); err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return accounts, nil
}
