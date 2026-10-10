package storage

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

// Repository persists audit events and provides bounded read access for the
// admin dashboard. It does not expose update or delete operations by design.
type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }
func (s *Repository) Write(ctx context.Context, event audit.Event) error {
	return write(ctx, s.pool, event)
}

// WriteTx projects an outbox fact inside the dispatch transaction.
func (s *Repository) WriteTx(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	return write(ctx, tx, event)
}

type executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func write(ctx context.Context, exec executor, event audit.Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return err
	}

	var eventID *string
	if event.ID != "" {
		eventID = &event.ID
	}

	_, err = exec.Exec(
		ctx,
		`INSERT INTO audit_events(event_id,occurred_at,actor_type,actor_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(event_id) DO NOTHING`,
		eventID,
		event.OccurredAt,
		event.ActorType,
		event.ActorID,
		event.Action,
		event.TargetType,
		event.TargetID,
		metadata,
	)

	return err
}

// List returns the newest audit entries first. The limit is clamped here at
// the persistence boundary as well as in HTTP, so a future non-HTTP consumer
// cannot accidentally request an unbounded history from the control database.
func (s *Repository) List(ctx context.Context, limit int) ([]audit.Event, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT occurred_at, actor_type, actor_id, action, target_type, target_id, metadata
		FROM audit_events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]audit.Event, 0, limit)
	for rows.Next() {
		var event audit.Event
		if err := rows.Scan(
			&event.OccurredAt,
			&event.ActorType,
			&event.ActorID,
			&event.Action,
			&event.TargetType,
			&event.TargetID,
			&event.Metadata,
		); err != nil {
			return nil, err
		}
		entries = append(entries, event)
	}
	return entries, rows.Err()
}
