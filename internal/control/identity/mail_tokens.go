package identity

import (
	"errors"
	"math"
	"time"
)

type MailPurpose string

const (
	MailAdminInvitation   MailPurpose = "admin_invitation"
	MailEmailVerification MailPurpose = "email_verification"
	MailPasswordReset     MailPurpose = "password_reset"
)

var ErrMailRateLimited = errors.New("account email request already pending")

// MailToken contains only a token hash. Its email, account epoch and purpose
// bind consumption to the authority that requested it; it is never a session.
type MailToken struct {
	Hash        [32]byte `json:"-"`
	AccountID   string
	Email       string
	AuthVersion uint64
	Purpose     MailPurpose
	CreatedAt   time.Time
	ExpiresAt   time.Time
}
type MailTokenUse struct {
	Hash         [32]byte `json:"-"`
	Purpose      MailPurpose
	Now          time.Time
	PasswordHash string `json:"-"`
}

func (t MailToken) Valid() bool {
	email, err := CanonicalEmail(t.Email)
	if err != nil || email != t.Email || t.Hash == ([32]byte{}) || t.AccountID == "" ||
		len(t.AccountID) > 128 ||
		t.AuthVersion == 0 ||
		t.AuthVersion > math.MaxInt64 ||
		t.CreatedAt.IsZero() ||
		!t.ExpiresAt.After(t.CreatedAt) {
		return false
	}

	var maximum time.Duration
	switch t.Purpose {
	case MailPasswordReset:
		maximum = 15 * time.Minute
	case MailAdminInvitation, MailEmailVerification:
		maximum = 24 * time.Hour
	default:
		return false
	}

	return t.ExpiresAt.Sub(t.CreatedAt) <= maximum
}
