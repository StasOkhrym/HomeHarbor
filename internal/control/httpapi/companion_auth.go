package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	companionChallengeTTL  = time.Minute
	maxCompanionChallenges = 256
)

var errCompanionChallengeUnavailable = errors.New("companion challenge store is full")

// companionChallengeStore is intentionally in-memory: challenges are short
// lived, single-use proof material, not durable application state. A control
// restart invalidates outstanding reads but does not affect signed snapshots.
type companionChallengeStore struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

func newCompanionChallengeStore() *companionChallengeStore {
	return &companionChallengeStore{nonces: make(map[string]time.Time)}
}

func (s *companionChallengeStore) issue(now time.Time) (string, time.Time, error) {
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
	s.nonces[nonce] = expiresAt
	return nonce, expiresAt, nil
}

func (s *companionChallengeStore) consume(nonce string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiresAt, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	delete(s.nonces, nonce)
	return expiresAt.After(now)
}
