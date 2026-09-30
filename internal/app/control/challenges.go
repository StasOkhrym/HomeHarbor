package control

import (
	"context"
	"errors"
	"time"

	"github.com/sokhrym/go-tunnels/internal/platform/redissecurity"
)

type sharedChallenges struct{ store *redissecurity.Store }

func (s sharedChallenges) PutChallenge(ctx context.Context, purpose, key string, value []byte, ttl time.Duration) error {
	return s.store.PutChallenge(ctx, purpose, key, value, ttl)
}

func (s sharedChallenges) ConsumeChallenge(ctx context.Context, purpose, key string) ([]byte, error) {
	value, err := s.store.ConsumeChallenge(ctx, purpose, key)
	if errors.Is(err, redissecurity.ErrChallengeMissing) {
		return nil, nil
	}
	return value, err
}
