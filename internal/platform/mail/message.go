// Package mail supplies bounded message values and canonical addresses shared
// by account workflows. It owns no invitations, queue or account authority.
package mail

import (
	"errors"
	netmail "net/mail"
	"strings"
	"time"
)

var ErrInvalidAddress = errors.New("invalid email address")

type Message struct {
	ID      string    `json:"-"`
	To      string    `json:"-"`
	Subject string    `json:"-"`
	Text    string    `json:"-"`
	Date    time.Time `json:"-"`
}

func CanonicalAddress(input string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(input))
	if len(value) < 3 || len(value) > 254 {
		return "", ErrInvalidAddress
	}

	parsed, err := netmail.ParseAddress(value)
	if err != nil || parsed.Address != value || parsed.Name != "" {
		return "", ErrInvalidAddress
	}

	return value, nil
}

// Delivery errors deliberately carry no server reply, address or message body.
var (
	ErrInvalidMessage = errors.New("invalid mail message")
	ErrTemporary      = errors.New("mail delivery temporarily unavailable")
	ErrPermanent      = errors.New("mail delivery rejected")
)
