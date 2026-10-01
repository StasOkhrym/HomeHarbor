package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ChallengeRepository preserves single-use proof consumption across processes.
type ChallengeRepository interface {
	PutChallenge(context.Context, string, string, []byte, time.Duration) error
	ConsumeChallenge(context.Context, string, string) ([]byte, error)
}

const (
	companionChallengeTTL  = time.Minute
	maxCompanionChallenges = 256
)

var errCompanionChallengeUnavailable = errors.New("companion challenge store is full")

// companionChallengeStore delegates production issuance/consumption to the
// shared Redis-backed port. The bounded memory map is a test adapter only;
// failure of an injected shared store never falls back to that map.
type companionChallengeStore struct {
	shared ChallengeRepository
	mu     sync.Mutex
	nonces map[string]time.Time
}

func newCompanionChallengeStore() *companionChallengeStore {
	return &companionChallengeStore{nonces: make(map[string]time.Time)}
}

func (s *companionChallengeStore) issue(ctx context.Context, now time.Time) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for nonce, expiresAt := range s.nonces {
		if !expiresAt.After(now) {
			delete(s.nonces, nonce)
		}
	}
	if len(s.nonces) >= maxCompanionChallenges {
		return "", time.Time{}, errCompanionChallengeUnavailable
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	expiresAt := now.Add(companionChallengeTTL)
	if s.shared != nil {
		if err := s.shared.PutChallenge(
			ctx,
			"companion-read",
			nonce,
			[]byte("read"),
			companionChallengeTTL,
		); err != nil {
			return "", time.Time{}, err
		}
		return nonce, expiresAt, nil
	}
	s.nonces[nonce] = expiresAt
	return nonce, expiresAt, nil
}

func (s *companionChallengeStore) consume(ctx context.Context, nonce string, now time.Time) (bool, error) {
	if s.shared != nil {
		value, err := s.shared.ConsumeChallenge(ctx, "companion-read", nonce)
		return len(value) != 0 && err == nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expiresAt, ok := s.nonces[nonce]
	if !ok {
		return false, nil
	}
	delete(s.nonces, nonce)
	return expiresAt.After(now), nil
}
