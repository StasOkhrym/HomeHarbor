// Package redissecurity provides bounded, short-lived security state. It never
// stores network authority, durable lockout, or device private key material.
package redissecurity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrChallengeMissing = errors.New("challenge missing or consumed")
	ErrUnavailable      = errors.New("security state unavailable")
)

// Store implements consumer-side challenge and rate-limit contracts. All
// consumers of a control deployment share its prefix, including after restart.
type Store struct {
	client redis.UniversalClient
	prefix string
}

func New(client redis.UniversalClient, prefix string) *Store {
	return &Store{client: client, prefix: prefix}
}

func (s *Store) key(purpose, key string) string {
	digest := sha256.Sum256([]byte(purpose + "\x00" + key))
	return s.prefix + ":" + hex.EncodeToString(digest[:])
}

// PutChallenge refuses replacement: a collision must never change the proof
// that an outstanding one-time nonce authorizes.
func (s *Store) PutChallenge(
	ctx context.Context,
	purpose, key string,
	value []byte,
	ttl time.Duration,
) error {
	if ttl < time.Millisecond || len(value) == 0 || len(value) > 64<<10 {
		return errors.New("invalid challenge bounds")
	}

	stored, err := s.client.SetNX(ctx, s.key(purpose, key), value, ttl).Result()
	if err != nil {
		return fmt.Errorf("%w: save challenge", ErrUnavailable)
	}
	if !stored {
		return errors.New("challenge already exists")
	}

	return nil
}

// ConsumeChallenge deletes and returns in one Redis operation. A timeout is
// ambiguous about consumption, so callers must request a fresh challenge;
// falling back to a local map would reopen the replay window.
func (s *Store) ConsumeChallenge(ctx context.Context, purpose, key string) ([]byte, error) {
	value, err := s.client.GetDel(ctx, s.key(purpose, key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrChallengeMissing
	}
	if err != nil {
		return nil, fmt.Errorf("%w: consume challenge", ErrUnavailable)
	}

	return value, nil
}

var rateScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return {count, redis.call('PTTL', KEYS[1])}
`)

// Allow starts a fixed window at the first request, atomically across control
// processes. Redis OOM/noeviction and transport failures never grant a request.
func (s *Store) Allow(
	ctx context.Context,
	bucket, key string,
	limit int,
	window time.Duration,
) (bool, time.Duration, error) {
	if limit < 1 || window < time.Millisecond {
		return false, 0, errors.New("invalid rate-limit bounds")
	}

	result, err := rateScript.Run(ctx, s.client, []string{s.key("rate:"+bucket, key)}, window.Milliseconds()).
		Int64Slice()
	if err != nil || len(result) != 2 || result[1] < 0 {
		return false, 0, ErrUnavailable
	}

	return result[0] <= int64(limit), time.Duration(result[1]) * time.Millisecond, nil
}
