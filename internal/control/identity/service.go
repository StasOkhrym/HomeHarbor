package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"time"
)

var ErrInvalidCredential = errors.New("invalid or expired credential")

type RecoveryCode struct {
	Hash      [32]byte
	CreatedAt time.Time
	UsedAt    *time.Time
}

type Session struct {
	Hash      [32]byte
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

type IssuedSession struct {
	Token     string
	ExpiresAt time.Time
}

type Store interface {
	SaveRecoveryCodes(context.Context, []RecoveryCode) error
	ConsumeRecoveryCode(context.Context, [32]byte, time.Time) error
	SaveSession(context.Context, Session) error
	Session(context.Context, [32]byte) (Session, error)
	RevokeSession(context.Context, [32]byte, time.Time) error
}

type Service struct {
	store  Store
	now    func() time.Time
	random io.Reader
}

func NewService(store Store, now func() time.Time, random io.Reader) *Service {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	return &Service{store: store, now: now, random: random}
}

func (s *Service) GenerateRecoveryCodes(ctx context.Context, count int) ([]string, error) {
	if count < 1 || count > 32 {
		return nil, errors.New("recovery code count must be between 1 and 32")
	}
	now := s.now().UTC()
	plaintext := make([]string, 0, count)
	records := make([]RecoveryCode, 0, count)
	for range count {
		code, err := s.randomToken(20)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, code)
		records = append(records, RecoveryCode{Hash: hashToken(code), CreatedAt: now})
	}
	// Persist the whole replacement set before returning any plaintext. This
	// prevents an operator from receiving codes that the server cannot consume.
	if err := s.store.SaveRecoveryCodes(ctx, records); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (s *Service) ConsumeRecoveryCode(ctx context.Context, plaintext string) error {
	if plaintext == "" {
		return ErrInvalidCredential
	}
	// Atomicity belongs to Store: multiple control replicas may race to consume
	// the same hash and exactly one transaction is allowed to update used_at.
	if err := s.store.ConsumeRecoveryCode(ctx, hashToken(plaintext), s.now().UTC()); err != nil {
		return ErrInvalidCredential
	}
	return nil
}

func (s *Service) CreateSession(ctx context.Context, ttl time.Duration) (IssuedSession, error) {
	if ttl <= 0 {
		return IssuedSession{}, errors.New("session TTL must be positive")
	}
	token, err := s.randomToken(32)
	if err != nil {
		return IssuedSession{}, err
	}
	now := s.now().UTC()
	session := Session{Hash: hashToken(token), CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err = s.store.SaveSession(ctx, session); err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{Token: token, ExpiresAt: session.ExpiresAt}, nil
}

func (s *Service) ValidateSession(ctx context.Context, plaintext string) (Session, error) {
	if plaintext == "" {
		return Session{}, ErrInvalidCredential
	}
	session, err := s.store.Session(ctx, hashToken(plaintext))
	if err != nil || session.RevokedAt != nil || !s.now().UTC().Before(session.ExpiresAt) {
		// Deliberately collapse missing, expired, and revoked states so callers do
		// not gain a token-enumeration oracle from different errors.
		return Session{}, ErrInvalidCredential
	}
	return session, nil
}

func (s *Service) RevokeSession(ctx context.Context, plaintext string) error {
	if plaintext == "" {
		return ErrInvalidCredential
	}
	if err := s.store.RevokeSession(ctx, hashToken(plaintext), s.now().UTC()); err != nil {
		return ErrInvalidCredential
	}
	return nil
}

func (s *Service) randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(s.random, buffer); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func hashToken(plaintext string) [32]byte { return sha256.Sum256([]byte(plaintext)) }
