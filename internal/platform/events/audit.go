package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

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
