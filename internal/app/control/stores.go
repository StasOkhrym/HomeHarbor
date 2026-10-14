package control

import (
	"context"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

// runtimeStores closes acquired resources in reverse order, at most once.
// Partial construction and runtime shutdown share the same ownership boundary.
type runtimeStores struct {
	pool    *pgxpool.Pool
	redis   *redis.Client
	closers []func()
	once    sync.Once
}

func (s *runtimeStores) close() {
	s.once.Do(func() {
		for i := len(s.closers) - 1; i >= 0; i-- {
			s.closers[i]()
		}
	})
}

func openStores(
	ctx context.Context,
	cfg config.Control,
) (*runtimeStores, error) {
	stores := &runtimeStores{}
	keep := false
	defer func() {
		if !keep {
			stores.close()
		}
	}()

	if cfg.Database.Driver != "" && cfg.Database.Driver != "postgres" {
		return nil, errors.New("unsupported database driver")
	}
	if cfg.Redis.URL == "" || cfg.Redis.Password == "" {
		return nil, errors.New("redis endpoint and resolved password are required")
	}

	redisOptions, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, errors.New("invalid Redis endpoint")
	}

	redisOptions.Password = cfg.Redis.Password
	redisOptions.DialTimeout = cfg.Runtime.RedisTimeout
	redisOptions.ReadTimeout = cfg.Runtime.RedisTimeout
	redisOptions.WriteTimeout = cfg.Runtime.RedisTimeout
	// Socket defaults are upper bounds; an earlier request/session deadline
	// must also reach the transport, otherwise a late reply can become success.
	redisOptions.ContextTimeoutEnabled = true
	redisClient := redis.NewClient(redisOptions)
	stores.redis = redisClient
	stores.closers = append(stores.closers, func() { _ = redisClient.Close() })

	if err := redisClient.Ping(ctx).Err(); err != nil {
		return nil, errors.New("redis security state unavailable")
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return nil, errors.Join(errors.New("parse database configuration"), err)
	}

	if cfg.Database.Password != "" {
		poolConfig.ConnConfig.Password = cfg.Database.Password
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.Join(errors.New("connect database"), err)
	}

	stores.pool = pool
	stores.closers = append(stores.closers, pool.Close)

	if err := pool.Ping(ctx); err != nil {
		return nil, errors.Join(errors.New("ping database"), err)
	}

	keep = true

	return stores, nil
}
