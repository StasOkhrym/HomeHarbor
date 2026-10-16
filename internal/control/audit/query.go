package audit

import (
	"errors"
	"time"
)

const (
	DefaultQueryLimit = 100
	MaxQueryLimit     = 200
)

// RecordID is the database identity of a committed audit row. Event.ID is a
// separate optional delivery identity and may be empty for direct auth events.
type Record struct {
	RecordID int64 `json:"record_id"`
	Event    Event `json:"event"`
}

// Query asks for a bounded newest-first audit window or older history.
// BeforeID is exclusive; zero selects the most recent committed rows.
type Query struct {
	Limit    int
	BeforeID int64
	Action   string
	TargetID string
	Category string
	Outcome  string
	ActorID  string
	DeviceID string
	Since    time.Time
	Until    time.Time
}

// Validate rejects unsupported facets before they can silently broaden a query.
func (q Query) Validate() error {
	if _, ok := CategoryActions(q.Category); !ok {
		return errors.New("choose a valid activity category")
	}

	switch q.Outcome {
	case "", "success", "failure", "unknown":
	default:
		return errors.New("choose a valid activity outcome")
	}

	if !q.Since.IsZero() && !q.Until.IsZero() && !q.Since.Before(q.Until) {
		return errors.New("activity time bounds must increase")
	}

	for _, value := range []string{q.Action, q.TargetID, q.ActorID, q.DeviceID} {
		if len(value) > 128 {
			return errors.New("activity filters are too long")
		}
	}

	return nil
}
