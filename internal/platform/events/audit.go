package events

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
)

// RunOutboxDispatcher delivers committed domain events to Watermill with
// at-least-once semantics. A crash after publish and before marking the row can
// duplicate an audit event; consumers must therefore remain idempotent.
func RunOutboxDispatcher(
	ctx context.Context,
	pool *pgxpool.Pool,
	publisher OutboxPublisher,
	logger *slog.Logger,
) error {
	if pool == nil || publisher == nil {
		return errors.New("outbox dependencies are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := dispatchOutboxBatch(ctx, pool, publisher); err != nil && ctx.Err() == nil {
			logger.Error("dispatch event outbox", "error", err)
			// A stopped critical consumer is a runtime failure, not successful
			// readiness. Supervision stops HTTP and leaves rows pending for restart.
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// OutboxPublisher acknowledges only after critical durable consumers succeed.
type OutboxPublisher interface {
	Publish(context.Context, string, *message.Message) error
}

func dispatchOutboxBatch(ctx context.Context, pool *pgxpool.Pool, publisher OutboxPublisher) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(
		ctx,
		`SELECT id,topic,payload FROM event_outbox WHERE published_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 50`,
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	type event struct {
		id      int64
		topic   string
		payload []byte
	}
	var events []event
	for rows.Next() {
		var item event
		if err := rows.Scan(&item.id, &item.topic, &item.payload); err != nil {
			return err
		}
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, item := range events {
		msg := message.NewMessage("outbox:"+strconv.FormatInt(item.id, 10), item.payload)
		if err := publisher.Publish(ctx, item.topic, msg); err != nil {
			// Roll back the whole claimed batch. Earlier durable receipts may
			// be replayed with the same event ID; failed attempts are logged by
			// the supervisor, not falsely "persisted" in a transaction we abort.
			return err
		}
		if _, err := tx.Exec(
			ctx,
			`UPDATE event_outbox SET published_at=now(),attempts=attempts+1,last_error=NULL WHERE id=$1`,
			item.id,
		); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type AuditSink interface {
	Write(context.Context, audit.Event) error
}

// IdentityAuditor reduces auth activity to non-sensitive durable events.
type IdentityAuditor struct {
	sink AuditSink
	now  func() time.Time
}

// NewIdentityAuditor accepts a clock so event timestamps remain deterministic in tests.
func NewIdentityAuditor(sink AuditSink, now func() time.Time) *IdentityAuditor {
	if now == nil {
		now = time.Now
	}
	return &IdentityAuditor{sink: sink, now: now}
}

// RecordIdentity persists an outcome and deliberately accepts no secret-bearing input.
func (a *IdentityAuditor) RecordIdentity(ctx context.Context, action string, success bool) error {
	// Authentication audit metadata is intentionally limited to outcome. Raw
	// WebAuthn responses, recovery codes, and session tokens must never reach a
	// durable log even when authentication fails.
	return a.sink.Write(
		ctx,
		audit.Event{
			OccurredAt: a.now().UTC(),
			ActorType:  "admin",
			ActorID:    "admin",
			Action:     action,
			TargetType: "admin_session",
			TargetID:   "admin",
			Metadata:   map[string]any{"success": success},
		},
	)
}
