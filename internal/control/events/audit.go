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
	facts := audit.FromContext(ctx).Safe()
	metadata := facts.Metadata()
	metadata["success"] = success
	targetType := "admin_session"
	switch action {
	case "admin.account_configured",
		"admin.totp_added",
		"admin.totp_removed",
		"admin.passkey_added",
		"admin.passkey_removed",
		"admin.recovery_codes_replaced":
		targetType = "admin_account"
	}

	return a.sink.Write(ctx, audit.Event{
		OccurredAt: a.now().UTC(), ActorType: facts.ActorType, ActorID: facts.ActorID,
		Action: action, TargetType: targetType, TargetID: facts.ActorID,
		Metadata: metadata,
	})
}
