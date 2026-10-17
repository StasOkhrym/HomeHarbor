package events

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
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
