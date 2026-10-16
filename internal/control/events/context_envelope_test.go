package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

func TestContextEnvelopeRoundTripAndLegacyCompatibility(t *testing.T) {
	event := devices.Event{
		Type:        "device.revoked",
		AggregateID: "device-1",
		OccurredAt:  time.Now().UTC(),
	}
	facts := audit.Context{
		ActorType:     "admin",
		ActorID:       "account-1",
		ActorName:     "Olena",
		SourceIP:      "192.0.2.9",
		CorrelationID: "request-1",
	}
	subject := audit.SubjectSnapshot{
		Name:          "Kitchen Mac",
		Role:          "client",
		Platform:      "macos",
		OSVersion:     "15.0",
		ClientVersion: "0.1.0",
		OverlayIP:     "10.243.0.1",
	}

	envelope, err := FromDeviceEventWithContext(event, facts, subject)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := Decode(1, data)
	if err != nil {
		t.Fatal(err)
	}

	got := decoded.AuditEvent()

	if got.ActorID != "account-1" || got.Metadata["target_name"] != "Kitchen Mac" ||
		got.Metadata["source_ip"] != "192.0.2.9" ||
		got.Metadata["outcome"] != "success" ||
		got.Metadata["overlay_ip"] != "10.243.0.1" {
		t.Fatalf("lost context: %+v", got)
	}

	// A historic row carries no assertion about identity or outcome.
	old := []byte(
		`{"event_id":"old","type":"device.revoked","schema_version":1,"aggregate_id":"device-1","occurred_at":"2026-10-01T00:00:00Z","actor_type":"unknown","actor_id":"","target_type":"device","target_id":"device-1","payload":{}}`,
	)

	legacy, err := Decode(2, old)
	if err != nil {
		t.Fatal(err)
	}

	if legacy.ActorType != "unknown" || len(legacy.AuditEvent().Metadata) != 0 {
		t.Fatalf("invented historic facts: %+v", legacy)
	}
}

func TestEnvelopeRejectsUnsafePersistedContext(t *testing.T) {
	fact, err := FromDeviceEvent(
		devices.Event{Type: "device.enrolled", AggregateID: "d-1", OccurredAt: time.Now()},
	)
	if err != nil {
		t.Fatal(err)
	}

	fact.Payload.Context = audit.Context{SourceIP: "SECRET_TOKEN"}

	data, _ := json.Marshal(fact)

	if _, err := Decode(1, data); err == nil {
		t.Fatal("unsafe context accepted from durable row")
	}
}
