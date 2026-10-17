package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

// Sessions stores only hashed browser identifiers and scoped authority references. Its versioned
// namespace is the sole session authority after upgrade: old SQL sessions are
// deliberately not imported, so existing browsers must authenticate again.
type Sessions struct {
	client  redisclient.UniversalClient
	prefix  string
	now     func() time.Time
	timeout time.Duration
}

// NewSessions uses one validated operation timeout for every Redis request.
func NewSessions(
	client redisclient.UniversalClient,
	prefix string,
	now func() time.Time,
	timeout time.Duration,
) (*Sessions, error) {
	if client == nil || timeout <= 0 {
		return nil, errors.New("session client and positive operation timeout are required")
	}

	if now == nil {
		now = time.Now
	}

	return &Sessions{
		client:  client,
		prefix:  prefix + ":browser-session:principal:",
		now:     now,
		timeout: timeout,
	}, nil
}

func (s *Sessions) key(hash [32]byte) string {
	return s.prefix + hex.EncodeToString(hash[:])
}

func (s *Sessions) SaveSession(ctx context.Context, session identity.Session) error {
	ttl := session.ExpiresAt.Sub(s.now())
	if ttl < time.Millisecond || !session.ExpiresAt.After(session.CreatedAt) ||
		session.RevokedAt != nil {
		return identity.ErrInvalidCredential
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}

	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	stored, err := s.client.SetNX(operation, s.key(session.Hash), payload, ttl).Result()
	if err != nil {
		return identity.ErrSecurityStateUnavailable
	}
	if !stored {
		return identity.ErrInvalidCredential
	}

	return nil
}

func (s *Sessions) Session(ctx context.Context, hash [32]byte) (identity.Session, error) {
	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	payload, err := s.client.Get(operation, s.key(hash)).Bytes()
	if errors.Is(err, redisclient.Nil) {
		return identity.Session{}, identity.ErrInvalidCredential
	}
	if err != nil {
		return identity.Session{}, identity.ErrSecurityStateUnavailable
	}

	var session identity.Session
	if len(payload) > 1024 || json.Unmarshal(payload, &session) != nil || session.Hash != hash {
		return identity.Session{}, identity.ErrSecurityStateUnavailable
	}
	if session.RevokedAt != nil || !s.now().Before(session.ExpiresAt) {
		return identity.Session{}, identity.ErrInvalidCredential
	}

	return session, nil
}

func (s *Sessions) RevokeSession(ctx context.Context, hash [32]byte, _ time.Time) error {
	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// DEL is atomic and idempotent: a lost logout response can be retried. A
	// timeout is not success; callers must not pretend revocation was confirmed.
	if err := s.client.Del(operation, s.key(hash)).Err(); err != nil {
		return identity.ErrSecurityStateUnavailable
	}

	return nil
}

var _ identity.SessionRepository = (*Sessions)(nil)
