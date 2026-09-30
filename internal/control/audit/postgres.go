package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Event is the append-only record shown to operators and retained for
// incident investigation. Metadata is intentionally opaque to this package;
// producers decide which domain facts are safe to record.
type Event struct {
	OccurredAt time.Time      `json:"occurred_at"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Metadata   map[string]any `json:"metadata"`
}

// PostgresSink persists audit events and provides bounded read access for the
// admin dashboard. It does not expose update or delete operations by design.
type PostgresSink struct{ pool *pgxpool.Pool }

func NewPostgresSink(pool *pgxpool.Pool) *PostgresSink { return &PostgresSink{pool: pool} }
func (s *PostgresSink) Write(ctx context.Context, event Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO audit_events(occurred_at,actor_type,actor_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,$4,$5,$6,$7)`, event.OccurredAt, event.ActorType, event.ActorID, event.Action, event.TargetType, event.TargetID, metadata)
	return err
}

// List returns the newest audit entries first. The limit is clamped here at
// the persistence boundary as well as in HTTP, so a future non-HTTP consumer
// cannot accidentally request an unbounded history from the control database.
func (s *PostgresSink) List(ctx context.Context, limit int) ([]Event, error) {
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
	entries := make([]Event, 0, limit)
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.OccurredAt, &event.ActorType, &event.ActorID, &event.Action, &event.TargetType, &event.TargetID, &event.Metadata); err != nil {
			return nil, err
		}
		entries = append(entries, event)
	}
	return entries, rows.Err()
}
