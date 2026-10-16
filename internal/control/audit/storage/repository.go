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

// ListRecords returns a bounded committed window ordered by storage identity.
// A fresh recent-window query can catch lower IDs that commit after higher IDs
// while they remain within the bounded window. Live refresh cannot rely only
// on an id > cursor predicate.
func (s *Repository) ListRecords(ctx context.Context, query audit.Query) ([]audit.Record, error) {
	if err := query.Validate(); err != nil {
		return nil, err
	}

	limit := query.Limit
	if limit < 1 {
		limit = audit.DefaultQueryLimit
	}

	if limit > audit.MaxQueryLimit {
		limit = audit.MaxQueryLimit
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

	if query.Category != "" {
		actions, _ := audit.CategoryActions(query.Category)
		args = append(args, actions)
		if query.Category == "system" {
			statement += fmt.Sprintf(" AND NOT (action = ANY($%d::text[]))", len(args))
		} else {
			statement += fmt.Sprintf(" AND action = ANY($%d::text[])", len(args))
		}
	}

	if query.Outcome != "" {
		// Match the presentation rule: a real boolean takes precedence over outcome;
		// strings that look like booleans never become successful authentication.
		result := `CASE WHEN jsonb_typeof(metadata->'success')='boolean'
 THEN CASE WHEN metadata->>'success'='true' THEN 'success' ELSE 'failure' END
 WHEN metadata->>'outcome' IN ('success','failure') THEN metadata->>'outcome'
 ELSE 'unknown' END`
		args = append(args, query.Outcome)
		statement += fmt.Sprintf(" AND (%s) = $%d", result, len(args))
	}

	if query.ActorID != "" {
		args = append(args, query.ActorID)
		statement += fmt.Sprintf(" AND actor_type='admin' AND actor_id=$%d", len(args))
	}

	if query.DeviceID != "" {
		args = append(args, query.DeviceID)
		statement += fmt.Sprintf(
			" AND ((target_type='device' AND target_id=$%d) OR (actor_type='device' AND actor_id=$%d))",
			len(args),
			len(args),
		)
	}

	if !query.Since.IsZero() {
		args = append(args, query.Since.UTC())
		statement += fmt.Sprintf(" AND occurred_at >= $%d", len(args))
	}

	if !query.Until.IsZero() {
		args = append(args, query.Until.UTC())
		statement += fmt.Sprintf(" AND occurred_at < $%d", len(args))
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
