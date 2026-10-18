package transactions

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	identitypg "github.com/StasOkhrym/homeharbor/internal/control/identity/storage"
	notificationpg "github.com/StasOkhrym/homeharbor/internal/control/notifications/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/workflows"
)

type AccountMailUnitOfWork struct{ pool *pgxpool.Pool }

func NewAccountMailUnitOfWork(pool *pgxpool.Pool) *AccountMailUnitOfWork {
	return &AccountMailUnitOfWork{pool: pool}
}

func (u *AccountMailUnitOfWork) WithinAccountMail(
	ctx context.Context,
	fn func(workflows.AccountMailTransaction) error,
) error {
	tx, err := u.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()

		_ = tx.Rollback(cleanup)
	}()

	if err := fn(
		workflows.AccountMailTransaction{
			Accounts:   identitypg.Bind(tx),
			Deliveries: notificationpg.Bind(tx),
		},
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

var _ workflows.AccountMailUnitOfWork = (*AccountMailUnitOfWork)(nil)
