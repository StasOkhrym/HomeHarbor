package notifications

import "errors"

var (
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
