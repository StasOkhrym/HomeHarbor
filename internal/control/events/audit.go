package events

import (
	"context"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
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
