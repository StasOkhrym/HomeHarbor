package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrExpiredTicket = errors.New("relay ticket expired")
	ErrInvalidTicket = errors.New("invalid relay ticket")
)

const (
	TicketVersion   = 1
	RelayAudience   = "relay"
	maxTicketLength = 4096
)

type TicketClaims struct {
	TicketID            string `json:"jti,omitempty"`
	Version             int    `json:"v"`
	Audience            string `json:"aud"`
	SessionID           string `json:"sid"`
	DeviceID            string `json:"did"`
	DestinationDeviceID string `json:"dst,omitempty"`
	ExpiresAt           int64  `json:"exp"`
}
type TicketIssuer struct {
	Key []byte
	Now func() time.Time
}

func (i TicketIssuer) Issue(sessionID, deviceID string, ttl time.Duration) (string, error) {
	return i.issue(sessionID, deviceID, "", ttl)
}

// IssueForPeer binds a relay credential to the exact peer it may reach. The
// WebSocket transport still accepts legacy unbound tickets, while the UDP
// pair transport requires this stronger claim before it can bind an address.
func (i TicketIssuer) IssueForPeer(
	sessionID, deviceID, destinationDeviceID string,
	ttl time.Duration,
) (string, error) {
	return i.issue(sessionID, deviceID, destinationDeviceID, ttl)
}

func (i TicketIssuer) issue(
	sessionID, deviceID, destinationDeviceID string,
	ttl time.Duration,
) (string, error) {
	if len(i.Key) < 32 {
		return "", errors.New("relay ticket key must be at least 32 bytes")
	}
	if sessionID == "" || deviceID == "" || ttl <= 0 {
		return "", errors.New("session, device, and positive TTL are required")
	}
	if destinationDeviceID == deviceID {
		return "", errors.New("relay destination must be a different device")
	}
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	// A fresh admission/rebind must not replay a credential issued in the same
	// second. Older transports can still verify claims without this field.
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate ticket ID: %w", err)
	}
	payload, err := json.Marshal(
		TicketClaims{
			TicketID:            base64.RawURLEncoding.EncodeToString(nonce[:]),
			Version:             TicketVersion,
			Audience:            RelayAudience,
			SessionID:           sessionID,
			DeviceID:            deviceID,
			DestinationDeviceID: destinationDeviceID,
			ExpiresAt:           now().Add(ttl).Unix(),
		},
	)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + i.sign(encoded), nil
}

func (i TicketIssuer) Verify(token string) (TicketClaims, error) {
	var claims TicketClaims
	if len(i.Key) < 32 || len(token) == 0 || len(token) > maxTicketLength {
		return claims, ErrInvalidTicket
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(i.sign(parts[0])), []byte(parts[1])) {
		return claims, ErrInvalidTicket
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, ErrInvalidTicket
	}

	if err = json.Unmarshal(payload, &claims); err != nil {
		return claims, ErrInvalidTicket
	}

	if claims.Version != TicketVersion || claims.Audience != RelayAudience ||
		claims.SessionID == "" ||
		claims.DeviceID == "" ||
		claims.ExpiresAt <= 0 {
		return TicketClaims{}, ErrInvalidTicket
	}

	now := time.Now
	if i.Now != nil {
		now = i.Now
	}

	if now().Unix() >= claims.ExpiresAt {
		return claims, ErrExpiredTicket
	}

	return claims, nil
}

func (i TicketIssuer) sign(value string) string {
	mac := hmac.New(sha256.New, i.Key)
	_, _ = mac.Write([]byte(value))

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (c TicketClaims) Validate(sessionID, deviceID string) error {
	if c.SessionID != sessionID || c.DeviceID != deviceID {
		return fmt.Errorf("ticket subject mismatch")
	}

	return nil
}

func (c TicketClaims) ValidatePeer(sessionID, deviceID, destinationDeviceID string) error {
	if err := c.Validate(sessionID, deviceID); err != nil {
		return err
	}

	if c.DestinationDeviceID != destinationDeviceID {
		return fmt.Errorf("ticket destination mismatch")
	}

	return nil
}
