package events

import (
	"context"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
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

// RecordAccount keeps the proven account target separate from the caller.
// Mailbox proof establishes a target, never an authenticated owner actor.
func (a *IdentityAuditor) RecordAccount(
	ctx context.Context,
	action string,
	subject identity.AccountSubject,
	success bool,
) error {
	facts := audit.FromContext(ctx).Safe()
	metadata := facts.Metadata()
	metadata["success"] = success
	for key, value := range (audit.SubjectSnapshot{Name: subject.Email}).Metadata() {
		metadata[key] = value
	}

	id := subject.ID
	if !audit.PublicText(id, 128) {
		id = ""
	}

	return a.sink.Write(
		ctx,
		audit.Event{
			OccurredAt: a.now().UTC(),
			ActorType:  facts.ActorType,
			ActorID:    facts.ActorID,
			Action:     action,
			TargetType: "admin_account",
			TargetID:   id,
			Metadata:   metadata,
		},
	)
}
