// Package transactions provides use-case-specific PostgreSQL transaction adapters.
package transactions

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	devicepg "github.com/StasOkhrym/homeharbor/internal/control/devices/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/events"
	invitepg "github.com/StasOkhrym/homeharbor/internal/control/invites/storage"
	profilepg "github.com/StasOkhrym/homeharbor/internal/control/profiles/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/workflows"
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
	facts := audit.FromContext(ctx)
	var subject audit.SubjectSnapshot
	if event.Type != "invite.approved" {
		value, role, err := devicepg.Bind(tx).PublicMetadata(ctx, event.AggregateID)
		if err != nil {
			return err
		}

		subject = audit.SubjectSnapshot{
			Name:          value.Name,
			Role:          string(role),
			Platform:      value.Platform,
			OSVersion:     value.OSVersion,
			ClientVersion: value.ClientVersion,
		}
		// These facts are published only after successful possession checks in the
		// same transaction. Aggregate IDs alone never establish any other actor.
		switch event.Type {
		case "device.credential_rotated",
			"device.credential_recovered",
			"device.credential_claimed":
			facts.ActorType, facts.ActorID, facts.ActorName = "device", event.AggregateID, value.Name
			facts.Authentication = "identity_proof"
			if event.Type == "device.credential_rotated" {
				facts.Authentication = "device_credential"
			}
		}
	}

	fact, err := events.FromDeviceEventWithContext(event, facts, subject)
	if err != nil {
		return err
	}

	return AppendFact(ctx, tx, fact)
}

// AppendFact keeps the durable fact in the caller's business transaction.
func AppendFact(ctx context.Context, tx pgx.Tx, fact events.Envelope) error {
	if err := fact.Validate(); err != nil {
		return err
	}

	payload, err := json.Marshal(fact)
	if err != nil {
		return err
	}

	_, err = tx.Exec(
		ctx,
		`INSERT INTO event_outbox(topic,payload,occurred_at) VALUES($1,$2,$3)`,
		fact.Type,
		payload,
		fact.OccurredAt,
	)

	return err
}

var _ workflows.ActivationUnitOfWork = (*ActivationUnitOfWork)(nil)
