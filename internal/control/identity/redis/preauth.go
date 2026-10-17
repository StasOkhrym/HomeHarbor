package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

type Preauth struct {
	client  redisclient.UniversalClient
	prefix  string
	now     func() time.Time
	timeout time.Duration
}

func NewPreauth(
	client redisclient.UniversalClient,
	prefix string,
	now func() time.Time,
	timeout time.Duration,
) (*Preauth, error) {
	if client == nil || timeout <= 0 {
		return nil, errors.New("preauth client and positive timeout required")
	}

	if now == nil {
		now = time.Now
	}

	return &Preauth{
		client:  client,
		prefix:  prefix + ":password-preauth:",
		now:     now,
		timeout: timeout,
	}, nil
}
func (s *Preauth) key(hash [32]byte) string { return s.prefix + hex.EncodeToString(hash[:]) }
func (s *Preauth) SavePreauth(ctx context.Context, record identity.Preauth) error {
	ttl := record.ExpiresAt.Sub(s.now())
	if ttl < time.Millisecond || ttl > 5*time.Minute || record.AccountID == "" ||
		len(record.AccountID) > 128 ||
		record.AuthVersion == 0 ||
		record.Attempts != 0 ||
		record.CreatedAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) ||
		record.ExpiresAt.Sub(record.CreatedAt) > 5*time.Minute {
		return identity.ErrInvalidCredential
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return identity.ErrSecurityStateUnavailable
	}

	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	stored, err := preauthSave.Run(operation, s.client, []string{s.key(record.Hash)}, payload, ttl.Milliseconds()).
		Int()
	if err != nil {
		return identity.ErrSecurityStateUnavailable
	}
	if stored != 1 {
		return identity.ErrInvalidCredential
	}

	return nil
}

// Keep immutable proof JSON out of Lua's floating-point decoder. The epoch is
// a PostgreSQL bigint; even a valid value above 2^53 must retain exact identity.
var preauthSave = redisclient.NewScript(`
if redis.call('EXISTS',KEYS[1])==1 then return 0 end
redis.call('HSET',KEYS[1],'proof',ARGV[1],'attempts',0)
redis.call('PEXPIRE',KEYS[1],ARGV[2])
return 1
`)

var preauthAttempt = redisclient.NewScript(`
local payload=redis.call('HGET',KEYS[1],'proof')
if not payload then return {} end
local attempts=tonumber(redis.call('HGET',KEYS[1],'attempts'))
if not attempts or attempts<0 or attempts%1~=0 then return redis.error_reply('invalid preauth state') end
if attempts>=5 then return {} end
attempts=redis.call('HINCRBY',KEYS[1],'attempts',1)
return {payload,tostring(attempts)}
`)

var preauthConsume = redisclient.NewScript(`
local payload=redis.call('HGET',KEYS[1],'proof')
if not payload then return {} end
local attempts=redis.call('HGET',KEYS[1],'attempts')
redis.call('DEL',KEYS[1])
return {payload,attempts}
`)

func (s *Preauth) AttemptPreauth(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (identity.Preauth, error) {
	return s.run(ctx, preauthAttempt, hash, now)
}

func (s *Preauth) ConsumePreauth(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (identity.Preauth, error) {
	return s.run(ctx, preauthConsume, hash, now)
}

func (s *Preauth) run(
	ctx context.Context,
	script *redisclient.Script,
	hash [32]byte,
	now time.Time,
) (identity.Preauth, error) {
	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	values, err := script.Run(operation, s.client, []string{s.key(hash)}).StringSlice()
	if err != nil {
		return identity.Preauth{}, identity.ErrSecurityStateUnavailable
	}
	if len(values) == 0 {
		return identity.Preauth{}, identity.ErrInvalidCredential
	}
	if len(values) != 2 {
		return identity.Preauth{}, identity.ErrSecurityStateUnavailable
	}
	attempts, err := strconv.Atoi(values[1])
	if err != nil || attempts < 1 || attempts > 5 {
		return identity.Preauth{}, identity.ErrInvalidCredential
	}
	record, err := decodePreauth(values[0], nil, hash, now)
	record.Attempts = attempts
	return record, err
}

func decodePreauth(
	payload string,
	err error,
	hash [32]byte,
	now time.Time,
) (identity.Preauth, error) {
	if errors.Is(err, redisclient.Nil) {
		return identity.Preauth{}, identity.ErrInvalidCredential
	}
	if err != nil {
		return identity.Preauth{}, identity.ErrSecurityStateUnavailable
	}
	var record identity.Preauth
	if len(payload) > 1024 || json.Unmarshal([]byte(payload), &record) != nil ||
		record.Hash != hash ||
		record.AccountID == "" ||
		len(record.AccountID) > 128 ||
		record.AuthVersion == 0 ||
		record.CreatedAt.IsZero() ||
		now.Before(record.CreatedAt) ||
		!record.ExpiresAt.After(record.CreatedAt) ||
		record.ExpiresAt.Sub(record.CreatedAt) > 5*time.Minute ||
		record.Attempts != 0 {
		return identity.Preauth{}, identity.ErrSecurityStateUnavailable
	}
	if !now.Before(record.ExpiresAt) {
		return identity.Preauth{}, identity.ErrInvalidCredential
	}
	return record, nil
}

var _ identity.PreauthRepository = (*Preauth)(nil)
