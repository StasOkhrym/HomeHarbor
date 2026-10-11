package storage

import (
	"context"
	"encoding/json"
	"fmt"

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
	records, err := s.ListRecords(ctx, audit.Query{Limit: limit})
	if err != nil {
		return nil, err
	}
	entries := make([]audit.Event, 0, len(records))
	for _, record := range records {
		entries = append(entries, record.Event)
	}
	return entries, nil
}

// ListRecords returns a bounded committed window ordered by storage identity.
// A fresh recent-window query can catch lower IDs that commit after higher IDs
// while they remain within the bounded window. Live refresh cannot rely only
// on an id > cursor predicate.
func (s *Repository) ListRecords(ctx context.Context, query audit.Query) ([]audit.Record, error) {
	limit := query.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > 200 {
		limit = 200
	}
	statement := `SELECT id,event_id,occurred_at,actor_type,actor_id,action,target_type,target_id,metadata
 FROM audit_events WHERE true`
	args := make([]any, 0, 4)
	if query.BeforeID > 0 {
		args = append(args, query.BeforeID)
		statement += fmt.Sprintf(" AND id < $%d", len(args))
	}
	if query.Action != "" {
		args = append(args, query.Action)
		statement += fmt.Sprintf(" AND action = $%d", len(args))
	}
	if query.TargetID != "" {
		args = append(args, query.TargetID)
		statement += fmt.Sprintf(" AND target_id = $%d", len(args))
	}
	args = append(args, limit)
	statement += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]audit.Record, 0, limit)
	for rows.Next() {
		var record audit.Record
		var eventID *string
		if err := rows.Scan(&record.RecordID, &eventID,
			&record.Event.OccurredAt, &record.Event.ActorType, &record.Event.ActorID,
			&record.Event.Action, &record.Event.TargetType, &record.Event.TargetID,
			&record.Event.Metadata); err != nil {
			return nil, err
		}
		if eventID != nil {
			record.Event.ID = *eventID
		}
		records = append(records, record)
	}
	return records, rows.Err()
}
