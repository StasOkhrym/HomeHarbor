// Package audit defines the public records retained for incident investigation.
package audit

import "time"

// Event is the append-only record shown to operators and retained for
// incident investigation. Metadata is intentionally opaque to this package;
// producers decide which domain facts are safe to record.
type Event struct {
	// ID is the stable delivery identity for outbox events. Direct auth events
	// omit it and remain distinct even when their timestamps/outcomes coincide.
	ID         string         `json:"id,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Metadata   map[string]any `json:"metadata"`
}
