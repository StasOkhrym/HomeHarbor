package control

import (
	"context"
	"errors"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/platform/redissecurity"
)

type sharedChallenges struct {
	store   *redissecurity.Store
	timeout time.Duration
}

func (s sharedChallenges) PutChallenge(
	ctx context.Context,
	purpose, key string,
	value []byte,
	ttl time.Duration,
) error {
	ctx, cancel := s.bounded(ctx)
	defer cancel()

	return s.store.PutChallenge(ctx, purpose, key, value, ttl)
}

func (s sharedChallenges) ConsumeChallenge(
	ctx context.Context,
	purpose, key string,
) ([]byte, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()

	value, err := s.store.ConsumeChallenge(ctx, purpose, key)
	if errors.Is(err, redissecurity.ErrChallengeMissing) {
		return nil, nil
	}

	return value, err
}

func (s sharedChallenges) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	return context.WithTimeout(ctx, timeout)
}
