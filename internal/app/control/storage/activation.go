// Package postgres provides use-case-specific PostgreSQL transaction adapters.
package storage

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/app/control/workflows"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	devicepg "github.com/StasOkhrym/homeharbor/internal/control/devices/storage"
	invitepg "github.com/StasOkhrym/homeharbor/internal/control/invites/storage"
	profilepg "github.com/StasOkhrym/homeharbor/internal/control/services/storage"
)

type ActivationUnitOfWork struct{ pool *pgxpool.Pool }

func NewActivationUnitOfWork(pool *pgxpool.Pool) *ActivationUnitOfWork {
	return &ActivationUnitOfWork{pool: pool}
}

func (u *ActivationUnitOfWork) WithinActivation(
	ctx context.Context,
	fn func(workflows.ActivationTransaction) error,
) error {
	tx, err := u.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	ports := workflows.ActivationTransaction{
		Invites:  invitepg.Bind(tx),
		Devices:  devicepg.Bind(tx),
		Profiles: profilepg.Bind(tx),
		Outbox:   outbox{tx: tx},
	}
	if err = fn(ports); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

type outbox struct{ tx pgx.Tx }

func (o outbox) Append(ctx context.Context, event devices.Event) error {
	return AppendEvent(ctx, o.tx, event)
}

// AppendEvent is also the explicit devices adapter publication port. All
// outbox SQL belongs at the application boundary, not in module adapters.
func AppendEvent(ctx context.Context, tx pgx.Tx, event devices.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		ctx,
		`INSERT INTO event_outbox(topic,payload,occurred_at) VALUES($1,$2,$3)`,
		event.Type,
		payload,
		event.OccurredAt,
	)
	return err
}

var _ workflows.ActivationUnitOfWork = (*ActivationUnitOfWork)(nil)
