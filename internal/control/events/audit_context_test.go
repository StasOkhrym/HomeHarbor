package events

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestIdentityAuditUsesVerifiedContext(t *testing.T) {
	sink := &recordingAuditSink{}

	ctx := audit.WithContext(t.Context(), audit.Context{
		ActorType: "admin", ActorID: "account-1", ActorName: "Olena",
		SourceIP: "192.0.2.10", Browser: "Safari", Platform: "macos",
		Authentication: "password_passkey", CorrelationID: "request-1",
	})

	if err := NewIdentityAuditor(sink, nil).RecordIdentity(ctx, "admin.login", true); err != nil {
		t.Fatal(err)
	}

	if sink.event.ActorType != "admin" || sink.event.ActorID != "account-1" ||
		sink.event.Metadata["actor_name"] != "Olena" ||
		sink.event.Metadata["source_ip"] != "192.0.2.10" ||
		sink.event.Metadata["browser"] != "Safari" ||
		sink.event.Metadata["platform"] != "macos" ||
		sink.event.Metadata["auth_method"] != "password_passkey" ||
		sink.event.Metadata["correlation_id"] != "request-1" ||
		sink.event.Metadata["success"] != true {
		t.Fatalf("lost authenticated context: %+v", sink.event)
	}
}

func TestIdentityAuditNeverAttributesAnonymousFailureToOwner(t *testing.T) {
	sink := &recordingAuditSink{}

	if err := NewIdentityAuditor(
		sink,
		nil,
	).RecordIdentity(t.Context(), "admin.login", false); err != nil {
		t.Fatal(err)
	}

	if sink.event.ActorType != "unknown" || sink.event.ActorID != "" {
		t.Fatalf("anonymous failure attributed to %+v", sink.event)
	}
}

func TestIdentityAuditDropsUnsafeOptionalRequestFacts(t *testing.T) {
	sink := &recordingAuditSink{}

	ctx := audit.WithContext(t.Context(), audit.Context{
		SourceIP: "Bearer SECRET_IP", ActorName: "owner\r\nSECRET_NAME",
		Browser: "SECRET_BROWSER", Platform: "SECRET_PLATFORM",
		Authentication: "Bearer SECRET_AUTH", Reason: "error included SECRET_REASON",
		CorrelationID: "request\nSECRET_CORRELATION",
	})

	if err := NewIdentityAuditor(sink, nil).RecordIdentity(ctx, "admin.auth", false); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(sink.event)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(data), "SECRET") || sink.event.ActorType != "unknown" ||
		sink.event.ActorID != "" {
		t.Fatalf("unsafe fact reached audit: %s", data)
	}
}

func TestIdentityAuditDoesNotInventOwnerForUnattributedSuccess(t *testing.T) {
	sink := &recordingAuditSink{}

	if err := NewIdentityAuditor(
		sink,
		nil,
	).RecordIdentity(t.Context(), "admin.login", true); err != nil {
		t.Fatal(err)
	}

	if sink.event.ActorType != "unknown" || sink.event.ActorID != "" {
		t.Fatalf("unattributed success became global owner: %+v", sink.event)
	}
}

func TestFactorAuditTargetsPersonalAccountAndKnownActivity(t *testing.T) {
	sink := &recordingAuditSink{}

	ctx := audit.WithContext(
		t.Context(),
		audit.Context{
			ActorType:      "admin",
			ActorID:        "account-1",
			Authentication: "password_totp",
			Reason:         "invalid_proof",
			SourceIP:       "192.0.2.10",
		},
	)
	for _, action := range []string{"admin.totp_added", "admin.totp_removed", "admin.passkey_added", "admin.passkey_removed", "admin.recovery_codes_replaced"} {
		if err := NewIdentityAuditor(sink, nil).RecordIdentity(ctx, action, false); err != nil {
			t.Fatal(err)
		}

		if sink.event.TargetType != "admin_account" || sink.event.TargetID != "account-1" ||
			sink.event.Metadata["auth_method"] != "password_totp" ||
			sink.event.Metadata["reason"] != "invalid_proof" ||
			audit.ActionLabel(action) == "Other activity" {
			t.Fatalf("unusable factor history: %+v", sink.event)
		}
	}
}

func TestMailAuditKeepsProvenTargetSeparateFromAdministratorActor(t *testing.T) {
	sink := &recordingAuditSink{}
	recorder := NewIdentityAuditor(sink, nil)
	subject := identity.AccountSubject{ID: "invited-account", Email: "guest@example.test"}

	ctx := audit.WithContext(
		t.Context(),
		audit.Context{
			ActorType:      "admin",
			ActorID:        identity.OwnerAccountID,
			ActorName:      "owner@example.test",
			Authentication: "password_passkey",
			SourceIP:       "192.0.2.10",
		},
	)

	if err := recorder.RecordAccount(ctx, "admin.invited", subject, true); err != nil {
		t.Fatal(err)
	}

	event := audit.PublicEvent(sink.event)

	if event.ActorID != identity.OwnerAccountID || event.TargetID != subject.ID ||
		event.TargetType != "admin_account" ||
		event.Metadata["target_name"] != subject.Email ||
		event.Metadata["source_ip"] != "192.0.2.10" ||
		audit.ActionLabel(event.Action) == "Other activity" {
		t.Fatal("invitation history attributed target to its owner")
	}

	proof := audit.WithContext(
		t.Context(),
		audit.Context{Authentication: "identity_proof", SourceIP: "192.0.2.20"},
	)

	if err := recorder.RecordAccount(proof, "admin.password_reset", subject, true); err != nil {
		t.Fatal(err)
	}

	event = audit.PublicEvent(sink.event)

	if event.ActorType != "unknown" || event.ActorID != "" || event.TargetID != subject.ID ||
		event.Metadata["target_name"] != subject.Email ||
		event.Metadata["auth_method"] != "identity_proof" {
		t.Fatal("mailbox proof invented an administrative actor or lost target")
	}
}
