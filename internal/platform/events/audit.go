package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

// RunOutboxDispatcher delivers committed domain events to Watermill with
// at-least-once semantics. A crash after publish and before marking the row can
// duplicate an audit event; consumers must therefore remain idempotent.
func RunOutboxDispatcher(ctx context.Context, pool *pgxpool.Pool, publisher message.Publisher, logger *slog.Logger) error {
	if pool == nil || publisher == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := dispatchOutboxBatch(ctx, pool, publisher); err != nil && ctx.Err() == nil {
			logger.Error("dispatch event outbox", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func dispatchOutboxBatch(ctx context.Context, pool *pgxpool.Pool, publisher message.Publisher) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT id,topic,payload FROM event_outbox WHERE published_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 50`)
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
	for _, item := range events {
		msg := message.NewMessage(watermill.NewUUID(), item.payload)
		if err := publisher.Publish(item.topic, msg); err != nil {
			_, _ = tx.Exec(ctx, `UPDATE event_outbox SET attempts=attempts+1,last_error=$2 WHERE id=$1`, item.id, err.Error())
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE event_outbox SET published_at=now(),attempts=attempts+1,last_error=NULL WHERE id=$1`, item.id); err != nil {
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
	return a.sink.Write(ctx, audit.Event{OccurredAt: a.now().UTC(), ActorType: "admin", ActorID: "admin", Action: action, TargetType: "admin_session", TargetID: "admin", Metadata: map[string]any{"success": success}})
}

func ConsumeDeviceAudit(ctx context.Context, subscriber message.Subscriber, sink AuditSink, logger *slog.Logger, topics ...string) error {
	for _, topic := range topics {
		messages, err := subscriber.Subscribe(ctx, topic)
		if err != nil {
			return err
		}
		go func(topic string, messages <-chan *message.Message) {
			for msg := range messages {
				var event devices.Event
				if err := json.Unmarshal(msg.Payload, &event); err != nil {
					logger.Error("decode audit event", "topic", topic, "error", err)
					msg.Nack()
					continue
				}
				if err := sink.Write(ctx, audit.Event{OccurredAt: event.OccurredAt, ActorType: "device", ActorID: event.AggregateID, Action: event.Type, TargetType: "device", TargetID: event.AggregateID, Metadata: map[string]any{}}); err != nil {
					logger.Error("persist audit event", "topic", topic, "error", err)
					msg.Nack()
					continue
				}
				msg.Ack()
			}
		}(topic, messages)
	}
	return nil
}
