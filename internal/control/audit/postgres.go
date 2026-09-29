package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	OccurredAt time.Time
	ActorType  string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Metadata   map[string]any
}
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
