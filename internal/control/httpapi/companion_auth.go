package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"
)

// ChallengeRepository preserves single-use proof consumption across processes.
type ChallengeRepository interface {
	PutChallenge(context.Context, string, string, []byte, time.Duration) error
	ConsumeChallenge(context.Context, string, string) ([]byte, error)
}

// companionChallengeStore has one authority for issuing and consuming proofs.
// An ambiguous Redis failure never opens a process-local replay window.
type companionChallengeStore struct {
	shared ChallengeRepository
	ttl    time.Duration
}

func newCompanionChallengeStore(
	repository ChallengeRepository,
	ttl time.Duration,
) *companionChallengeStore {
	return &companionChallengeStore{shared: repository, ttl: ttl}
}

func (s *companionChallengeStore) issue(
	ctx context.Context,
	now time.Time,
) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}

	nonce := base64.RawURLEncoding.EncodeToString(raw)
	expiresAt := now.Add(s.ttl)

	if err := s.shared.PutChallenge(
		ctx,
		"companion-read",
		nonce,
		[]byte("read"),
		s.ttl,
	); err != nil {
		return "", time.Time{}, err
	}

	return nonce, expiresAt, nil
}

func (s *companionChallengeStore) consume(
	ctx context.Context,
	nonce string,
	_ time.Time,
) (bool, error) {
	value, err := s.shared.ConsumeChallenge(ctx, "companion-read", nonce)
	return len(value) != 0 && err == nil, err
}
