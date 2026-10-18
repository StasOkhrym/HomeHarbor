package notifications

import (
	"errors"
	"time"
)

var (
	ErrRateLimited     = errors.New("notification request rate limited")
	ErrUnavailable     = errors.New("notification state unavailable")
	ErrLogicalConflict = errors.New("logical notification already has different contents")
	ErrLeaseLost       = errors.New("notification delivery lease lost")
)

type Delivery struct {
	Prepared
	LeaseToken string `json:"-"`
	Attempt    int    `json:"attempt"`
}

type Outcome string

const (
	DeliverySent     Outcome = "sent"
	RetryDelivery    Outcome = "retry"
	PermanentFailure Outcome = "permanent_failure"
	InvalidPayload   Outcome = "invalid_payload"
)

// TestStatus projects durable delivery bookkeeping without recipient, payload,
// lease or provider text. Sent means SMTP acceptance, not inbox delivery.
type TestStatus struct {
	State         string     `json:"state"`
	Attempts      int        `json:"attempts"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	LastErrorCode string     `json:"last_error_code,omitempty"`
}
