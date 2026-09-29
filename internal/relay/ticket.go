package relay

import (
	"crypto/hmac"
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
	Version   int    `json:"v"`
	Audience  string `json:"aud"`
	SessionID string `json:"sid"`
	DeviceID  string `json:"did"`
	ExpiresAt int64  `json:"exp"`
}
type TicketIssuer struct {
	Key []byte
	Now func() time.Time
}

func (i TicketIssuer) Issue(sessionID, deviceID string, ttl time.Duration) (string, error) {
	if len(i.Key) < 32 {
		return "", errors.New("relay ticket key must be at least 32 bytes")
	}
	if sessionID == "" || deviceID == "" || ttl <= 0 {
		return "", errors.New("session, device, and positive TTL are required")
	}
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	payload, err := json.Marshal(TicketClaims{Version: TicketVersion, Audience: RelayAudience, SessionID: sessionID, DeviceID: deviceID, ExpiresAt: now().Add(ttl).Unix()})
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
	if claims.Version != TicketVersion || claims.Audience != RelayAudience || claims.SessionID == "" || claims.DeviceID == "" || claims.ExpiresAt <= 0 {
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
