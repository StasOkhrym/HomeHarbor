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
	AccountID   string         `json:"account_id"`
	AuthVersion uint64         `json:"auth_version"`
	Purpose     SessionPurpose `json:"purpose"`
	Method      string         `json:"method"`
	Hash        [32]byte
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}
type SessionRequest struct {
	AuthVersion uint64
	AccountID   string
	Purpose     SessionPurpose
	Method      string
	TTL         time.Duration
}
type IssuedSession struct {
	Token     string
	ExpiresAt time.Time
	Purpose   SessionPurpose
}
type Repository interface {
	SaveRecoveryCodes(context.Context, AccountScope, []RecoveryCode) error
	ConsumeRecoveryCode(context.Context, RecoveryUse) error
}
type AccountReader interface {
	Account(context.Context, string) (Account, error)
}

// Redis owns opaque browser sessions. SQL accounts remain the live authority
// for role/status and auth-version; neither store substitutes for the other.
type SessionRepository interface {
	SaveSession(context.Context, Session) error
	Session(context.Context, [32]byte) (Session, error)
	RevokeSession(context.Context, [32]byte, time.Time) error
}
type Service struct {
	store    Repository
	sessions SessionRepository
	accounts AccountReader
	now      func() time.Time
	random   io.Reader
}

func NewService(
	store Repository,
	sessions SessionRepository,
	accounts AccountReader,
	now func() time.Time,
	random io.Reader,
) *Service {
	if now == nil {
		now = time.Now
	}

	if random == nil {
		random = rand.Reader
	}

	return &Service{store: store, sessions: sessions, accounts: accounts, now: now, random: random}
}

// Scope carries the account epoch established by password/preauth. Legacy
// owner migration can resolve a setup-only epoch; full authority never can.
func (s *Service) recoveryScope(ctx context.Context, scope AccountScope) (AccountScope, error) {
	account, err := readAccount(ctx, s.accounts, scope.AccountID)
	if err != nil {
		return AccountScope{}, err
	}
	if scope.AuthVersion == 0 && scope.Purpose != SessionMigration {
		return AccountScope{}, ErrInvalidCredential
	}
	if scope.AuthVersion != 0 && scope.AuthVersion != account.AuthVersion {
		return AccountScope{}, ErrInvalidCredential
	}

	now := s.now().UTC()
	if _, err := account.Principal(
		Session{
			AccountID:   account.ID,
			AuthVersion: account.AuthVersion,
			Purpose:     scope.Purpose,
			Method:      "recovery",
			CreatedAt:   now,
			ExpiresAt:   now.Add(time.Minute),
		},
	); err != nil {
		return AccountScope{}, err
	}

	scope.AuthVersion = account.AuthVersion

	return scope, nil
}

func (s *Service) GenerateRecoveryCodes(
	ctx context.Context,
	scope AccountScope,
	count int,
) ([]string, error) {
	if count < 1 || count > 32 {
		return nil, errors.New("recovery code count must be between 1 and 32")
	}

	scope, err := s.recoveryScope(ctx, scope)
	if err != nil {
		return nil, err
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

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := s.store.SaveRecoveryCodes(operation, scope, records); err != nil {
		return nil, securityStoreError(err)
	}

	return plaintext, nil
}

func (s *Service) ConsumeRecoveryCode(
	ctx context.Context,
	scope AccountScope,
	plaintext string,
) error {
	if plaintext == "" {
		return ErrInvalidCredential
	}

	scope, err := s.recoveryScope(ctx, scope)
	if err != nil {
		return err
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return securityStoreError(
		s.store.ConsumeRecoveryCode(
			operation,
			RecoveryUse{Scope: scope, Hash: hashToken(plaintext), UsedAt: s.now().UTC()},
		),
	)
}

func (s *Service) CreateSession(
	ctx context.Context,
	request SessionRequest,
) (IssuedSession, error) {
	if request.TTL <= 0 {
		return IssuedSession{}, errors.New("session TTL must be positive")
	}

	account, err := readAccount(ctx, s.accounts, request.AccountID)
	if err != nil {
		return IssuedSession{}, err
	}
	if (request.Purpose == SessionAdmin && request.AuthVersion == 0) ||
		(request.AuthVersion != 0 && request.AuthVersion != account.AuthVersion) {
		return IssuedSession{}, ErrInvalidCredential
	}

	ttl := request.TTL
	if request.Purpose == SessionMigration {
		ttl = min(ttl, 5*time.Minute)
	}

	now := s.now().UTC()
	session := Session{
		AccountID:   account.ID,
		AuthVersion: account.AuthVersion,
		Purpose:     request.Purpose,
		Method:      request.Method,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	if _, err := account.Principal(session); err != nil {
		return IssuedSession{}, err
	}

	token, err := s.randomToken(32)
	if err != nil {
		return IssuedSession{}, err
	}

	session.Hash = hashToken(token)

	if err := s.sessions.SaveSession(ctx, session); err != nil {
		return IssuedSession{}, securityStoreError(err)
	}

	return IssuedSession{Token: token, ExpiresAt: session.ExpiresAt, Purpose: session.Purpose}, nil
}

func (s *Service) ValidateSession(ctx context.Context, plaintext string) (Principal, error) {
	if plaintext == "" {
		return Principal{}, ErrInvalidCredential
	}

	hash := hashToken(plaintext)
	session, err := s.sessions.Session(ctx, hash)
	if err != nil {
		return Principal{}, securityStoreError(err)
	}
	if session.Hash != hash || session.AccountID == "" || session.AuthVersion == 0 ||
		session.Purpose == "" ||
		session.Method == "" ||
		session.RevokedAt != nil ||
		!s.now().UTC().Before(session.ExpiresAt) {
		return Principal{}, ErrInvalidCredential
	}

	account, err := readAccount(ctx, s.accounts, session.AccountID)
	if err != nil {
		return Principal{}, err
	}

	return account.Principal(session)
}

func (s *Service) RevokeSession(ctx context.Context, plaintext string) error {
	if plaintext == "" {
		return ErrInvalidCredential
	}

	return securityStoreError(s.sessions.RevokeSession(ctx, hashToken(plaintext), s.now().UTC()))
}

func securityStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInvalidCredential) {
		return ErrInvalidCredential
	}

	return ErrSecurityStateUnavailable
}

func (s *Service) randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(s.random, buffer); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
func hashToken(plaintext string) [32]byte { return sha256.Sum256([]byte(plaintext)) }
