package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

const SchemaVersion = 2

// Payload is an allowlist of public audit facts. Credentials, codes, tokens,
// request bodies, and arbitrary metadata have no representation here.
type Payload struct {
	Outcome string                `json:"outcome,omitempty"`
	Context audit.Context         `json:"context,omitzero"`
	Subject audit.SubjectSnapshot `json:"subject,omitzero"`
}

// Envelope is the durable control-owned event fact stored in the SQL outbox.
type Envelope struct {
	EventID           string    `json:"event_id"`
	Type              string    `json:"type"`
	SchemaVersion     int       `json:"schema_version"`
	AggregateID       string    `json:"aggregate_id"`
	AggregateRevision int64     `json:"aggregate_revision,omitempty"`
	OccurredAt        time.Time `json:"occurred_at"`
	ActorType         string    `json:"actor_type"`
	ActorID           string    `json:"actor_id"`
	TargetType        string    `json:"target_type"`
	TargetID          string    `json:"target_id"`
	CorrelationID     string    `json:"correlation_id,omitempty"`
	Payload           Payload   `json:"payload"`
}

// FromDeviceEvent adapts the existing transactional producer port. Its input
// does not attest an actor, so none is inferred from the aggregate ID.
func FromDeviceEvent(event devices.Event) (Envelope, error) {
	targetType, err := targetTypeFor(event.Type)
	if err != nil {
		return Envelope{}, err
	}

	fact := Envelope{
		EventID: uuid.NewString(), Type: event.Type, SchemaVersion: SchemaVersion,
		AggregateID: event.AggregateID, OccurredAt: event.OccurredAt,
		ActorType: "unknown", TargetType: targetType, TargetID: event.AggregateID,
		Payload: Payload{},
	}

	return fact, fact.Validate()
}

// FromDeviceEventWithContext is used only by committed mutation producers.
// Successful transaction completion attests outcome, not actor identity.
func FromDeviceEventWithContext(
	event devices.Event,
	facts audit.Context,
	subject audit.SubjectSnapshot,
) (Envelope, error) {
	fact, err := FromDeviceEvent(event)
	if err != nil {
		return Envelope{}, err
	}

	facts = facts.Safe()
	fact.ActorType, fact.ActorID, fact.CorrelationID = facts.ActorType, facts.ActorID, facts.CorrelationID
	fact.Payload = Payload{Outcome: "success", Context: facts, Subject: subject.Safe()}

	return fact, fact.Validate()
}

func targetTypeFor(action string) (string, error) {
	switch action {
	case "device.enrolled",
		"device.revoked",
		"device.credential_rotated",
		"device.credential_recovered",
		"device.credential_claimed":
		return "device", nil
	case "invite.approved":
		return "invite", nil
	default:
		return "", errors.New("unsupported audit action")
	}
}

func (e Envelope) Validate() error {
	if e.EventID == "" || (e.SchemaVersion != 1 && e.SchemaVersion != SchemaVersion) ||
		e.Type == "" ||
		e.AggregateID == "" ||
		e.OccurredAt.IsZero() ||
		e.TargetType == "" ||
		e.TargetID == "" {
		return errors.New("invalid event envelope")
	}

	target, err := targetTypeFor(e.Type)
	if err != nil || e.TargetType != target || e.TargetID != e.AggregateID {
		return errors.New("invalid event envelope")
	}
	if e.ActorType == "" || (e.ActorType == "unknown" && e.ActorID != "") ||
		(e.ActorType != "unknown" && e.ActorID == "") {
		return errors.New("invalid event actor")
	}
	if e.Payload.Outcome != "" && e.Payload.Outcome != "success" && e.Payload.Outcome != "failure" {
		return errors.New("invalid event outcome")
	}
	if e.SchemaVersion == 1 &&
		(e.Payload.Context != (audit.Context{}) || e.Payload.Subject != (audit.SubjectSnapshot{})) {
		return errors.New("invalid legacy event payload")
	}

	if facts := e.Payload.Context; facts != (audit.Context{}) {
		if facts != facts.Safe() || facts.ActorType != e.ActorType || facts.ActorID != e.ActorID ||
			facts.CorrelationID != e.CorrelationID {
			return errors.New("invalid public event context")
		}
	}

	if e.Payload.Subject != e.Payload.Subject.Safe() {
		return errors.New("invalid public event subject")
	}

	return nil
}

func Decode(id int64, payload []byte) (Envelope, error) {
	var fields map[string]json.RawMessage

	if err := json.Unmarshal(payload, &fields); err != nil {
		return Envelope{}, errors.New("invalid event JSON")
	}

	_, versioned := fields["schema_version"]
	if !versioned {
		// Historical rows had exactly these three fields and no schema version.
		var old devices.Event
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&old); err != nil {
			return Envelope{}, errors.New("invalid legacy event")
		}

		target, err := targetTypeFor(old.Type)
		if err != nil || old.AggregateID == "" || old.OccurredAt.IsZero() {
			return Envelope{}, errors.New("invalid legacy event")
		}

		return Envelope{
			EventID: legacyID(id), Type: old.Type, SchemaVersion: SchemaVersion,
			AggregateID: old.AggregateID, OccurredAt: old.OccurredAt, ActorType: "unknown",
			TargetType: target, TargetID: old.AggregateID, Payload: Payload{},
		}, nil
	}

	var fact Envelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&fact); err != nil {
		return Envelope{}, errors.New("invalid event envelope")
	}

	if err := fact.Validate(); err != nil {
		return Envelope{}, err
	}

	return fact, nil
}

func (e Envelope) AuditEvent() audit.Event {
	metadata := e.Payload.Context.Metadata()
	for key, value := range e.Payload.Subject.Metadata() {
		metadata[key] = value
	}

	if e.Payload.Outcome != "" {
		metadata["outcome"] = e.Payload.Outcome
	}

	if e.AggregateRevision != 0 {
		metadata["aggregate_revision"] = e.AggregateRevision
	}

	if e.CorrelationID != "" {
		metadata["correlation_id"] = e.CorrelationID
	}

	return audit.Event{
		ID:         e.EventID,
		OccurredAt: e.OccurredAt,
		ActorType:  e.ActorType,
		ActorID:    e.ActorID,
		Action:     e.Type,
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Metadata:   metadata,
	}
}

func legacyID(id int64) string { return "outbox:" + strconv.FormatInt(id, 10) }
