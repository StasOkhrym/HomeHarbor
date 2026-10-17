// Package notifications owns private transactional mail preparation and durable
// delivery. Secret-bearing messages never use the public activity outbox.
package notifications

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/platform/mail"
	"github.com/StasOkhrym/homeharbor/internal/platform/sealed"
)

var ErrInvalidPayload = errors.New("invalid private notification")

type Kind string

const (
	AdminInvitation   Kind = "admin_invitation"
	EmailVerification Kind = "email_verification"
	PasswordReset     Kind = "password_reset"
	SecurityNotice    Kind = "security_notice"
	SMTPTest          Kind = "smtp_test"
)

// Intent is ephemeral. Only Prepare's encrypted result may be persisted.
type Intent struct {
	ID        string    `json:"-"`
	AccountID string    `json:"-"`
	Kind      Kind      `json:"-"`
	To        string    `json:"-"`
	Token     string    `json:"-"`
	CreatedAt time.Time `json:"-"`
	ExpiresAt time.Time `json:"-"`
}
type Prepared struct {
	ID          string    `json:"id"`
	AccountID   string    `json:"account_id"`
	Kind        Kind      `json:"kind"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Ciphertext  []byte    `json:"-"`
	Fingerprint [32]byte  `json:"-"`
}

type privatePayload struct {
	Origin    string
	ID        string
	AccountID string
	Kind      Kind
	To        string
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Codec struct {
	box            *sealed.Box
	fingerprintKey []byte
	origin         url.URL
}

func parseOrigin(origin string) (url.URL, error) {
	parsed, err := url.Parse(origin)
	if len(origin) > 2048 || err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return url.URL{}, ErrInvalidPayload
	}

	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return url.URL{}, ErrInvalidPayload
		}
	}

	parsed.Path = ""
	parsed.RawPath = ""

	return *parsed, nil
}

func NewCodec(master []byte, origin string) (*Codec, error) {
	parsed, err := parseOrigin(origin)
	if err != nil {
		return nil, err
	}

	box, err := sealed.New(master, "notifications.delivery")
	if err != nil {
		return nil, ErrInvalidPayload
	}

	key, err := hkdf.Key(sha256.New, master, nil, "homeharbor.notifications.logical-message", 32)
	if err != nil {
		return nil, ErrInvalidPayload
	}

	return &Codec{box: box, fingerprintKey: key, origin: parsed}, nil
}

func lifetime(kind Kind) (time.Duration, bool) {
	switch kind {
	case AdminInvitation, EmailVerification, SecurityNotice:
		return 24 * time.Hour, true
	case PasswordReset:
		return 15 * time.Minute, true
	case SMTPTest:
		return 5 * time.Minute, true
	default:
		return 0, false
	}
}

func validPayload(p privatePayload) bool {
	if _, err := parseOrigin(p.Origin); err != nil {
		return false
	}

	id, err := uuid.Parse(p.ID)
	if err != nil || id == uuid.Nil || id.String() != p.ID || len(p.AccountID) < 1 ||
		len(p.AccountID) > 128 {
		return false
	}

	address, err := mail.CanonicalAddress(p.To)
	if err != nil || address != p.To {
		return false
	}

	ttl, ok := lifetime(p.Kind)
	if !ok || p.CreatedAt.IsZero() || !p.ExpiresAt.After(p.CreatedAt) ||
		p.ExpiresAt.Sub(p.CreatedAt) > ttl {
		return false
	}
	if p.Kind == SecurityNotice || p.Kind == SMTPTest {
		return p.Token == ""
	}

	token, err := base64.RawURLEncoding.Strict().DecodeString(p.Token)
	defer clear(token)

	return err == nil && len(token) == 32
}

func (c *Codec) fingerprint(payload []byte) [32]byte {
	mac := hmac.New(sha256.New, c.fingerprintKey)
	_, _ = mac.Write(payload)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (c *Codec) Prepare(intent Intent) (Prepared, error) {
	address, err := mail.CanonicalAddress(intent.To)
	if err != nil {
		return Prepared{}, ErrInvalidPayload
	}

	payload := privatePayload{
		Origin:    c.origin.String(),
		ID:        intent.ID,
		AccountID: intent.AccountID,
		Kind:      intent.Kind,
		To:        address,
		Token:     intent.Token,
		CreatedAt: intent.CreatedAt.UTC().Truncate(time.Microsecond),
		ExpiresAt: intent.ExpiresAt.UTC().Truncate(time.Microsecond),
	}
	if !validPayload(payload) {
		return Prepared{}, ErrInvalidPayload
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return Prepared{}, ErrInvalidPayload
	}
	defer clear(raw)

	ciphertext, err := c.box.Seal(payload.ID, raw)
	if err != nil {
		return Prepared{}, ErrInvalidPayload
	}

	return Prepared{
		ID:          payload.ID,
		AccountID:   payload.AccountID,
		Kind:        payload.Kind,
		CreatedAt:   payload.CreatedAt,
		ExpiresAt:   payload.ExpiresAt,
		Ciphertext:  ciphertext,
		Fingerprint: c.fingerprint(raw),
	}, nil
}

func (c *Codec) Render(prepared Prepared, now time.Time) (mail.Message, error) {
	raw, err := c.box.Open(prepared.ID, prepared.Ciphertext)
	if err != nil {
		return mail.Message{}, ErrInvalidPayload
	}
	defer clear(raw)

	fingerprint := c.fingerprint(raw)
	if !hmac.Equal(fingerprint[:], prepared.Fingerprint[:]) {
		return mail.Message{}, ErrInvalidPayload
	}

	var payload privatePayload

	if err := json.Unmarshal(
		raw,
		&payload,
	); err != nil || !validPayload(payload) || payload.ID != prepared.ID || payload.AccountID != prepared.AccountID || payload.Kind != prepared.Kind || !payload.CreatedAt.Equal(prepared.CreatedAt) || !payload.ExpiresAt.Equal(prepared.ExpiresAt) || now.Before(payload.CreatedAt) ||
		!now.Before(payload.ExpiresAt) {
		return mail.Message{}, ErrInvalidPayload
	}

	subject, text, path := "", "", ""
	switch payload.Kind {
	case AdminInvitation:
		subject = "You are invited to administer HomeHarbor"
		text = "The network owner invited you to manage their HomeHarbor network. Set your password and a verification method to finish joining."
		path = "/admin/invitation"
	case EmailVerification:
		subject = "Confirm your HomeHarbor email"
		text = "Confirm this email address for your HomeHarbor administrator account."
		path = "/admin/verify-email"
	case PasswordReset:
		subject = "Reset your HomeHarbor password"
		text = "Use this link to choose a new password. Your passkeys and authenticator stay in place."
		path = "/admin/reset-password"
	case SecurityNotice:
		subject = "Your HomeHarbor account security changed"
		text = "Your HomeHarbor account security settings changed. If you did not make this change, contact your network owner."
	case SMTPTest:
		subject = "HomeHarbor email test"
		text = "Your HomeHarbor SMTP connection is working."
	}

	if path != "" {
		link, err := parseOrigin(payload.Origin)
		if err != nil {
			return mail.Message{}, ErrInvalidPayload
		}

		link.Path = path
		link.RawPath = ""
		link.Fragment = "token=" + payload.Token
		text += "\n\n" + link.String() + "\n\nThis link expires at " + payload.ExpiresAt.UTC().
			Format(time.RFC3339) +
			" and can be used once. If you did not expect this message, ignore it."
	}

	return mail.Message{
		ID:      payload.ID,
		To:      payload.To,
		Subject: subject,
		Text:    text + "\n",
		Date:    payload.CreatedAt,
	}, nil
}
