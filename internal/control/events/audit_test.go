package events

import (
	"context"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type recordingAuditSink struct{ event audit.Event }

func (s *recordingAuditSink) Write(_ context.Context, event audit.Event) error {
	s.event = event
	return nil
}

func TestIdentityAuditContainsOutcomeWithoutCredentialMaterial(t *testing.T) {
	sink := &recordingAuditSink{}

	now := time.Unix(100, 0).UTC()
	recorder := NewIdentityAuditor(sink, func() time.Time { return now })

	if err := recorder.RecordIdentity(context.Background(), "admin.login", false); err != nil {
		t.Fatal(err)
	}

	if sink.event.Action != "admin.login" || sink.event.Metadata["success"] != false {
		t.Fatalf("event = %#v", sink.event)
	}
	if len(sink.event.Metadata) != 1 {
		t.Fatalf("unexpected audit metadata = %#v", sink.event.Metadata)
	}
}
