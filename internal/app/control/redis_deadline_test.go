package control

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	identityredis "github.com/StasOkhrym/homeharbor/internal/control/identity/redis"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func TestRedisSessionTransportDeadlineContract(t *testing.T) {
	endpoint, database := os.Getenv("TEST_REDIS_URL"), os.Getenv("TEST_DATABASE_URL")
	if endpoint == "" || database == "" {
		t.Skip("isolated TEST_REDIS_URL and TEST_DATABASE_URL are required")
	}
	options, err := redisclient.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Control{
		Runtime:  config.DefaultRuntime(false),
		Redis:    config.Redis{URL: endpoint, Password: options.Password},
		Database: config.Database{Driver: "postgres", URL: database},
	}
	cfg.Runtime.RedisTimeout = time.Second
	stores, err := openStores(t.Context(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stores.close)
	sessions, err := identityredis.NewSessions(
		stores.redis,
		t.Name(),
		time.Now,
		20*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Pause the real disposable Redis server after warming the production
	// connection. Its delayed SET reply arrives inside the socket timeout but
	// outside the session deadline; hooks cannot substitute for this boundary.
	if err := stores.redis.Do(t.Context(), "CLIENT", "PAUSE", 200, "ALL").Err(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err = sessions.SaveSession(t.Context(), identity.Session{
		CreatedAt: now,
		ExpiresAt: now.Add(time.Minute),
	})
	if !errors.Is(err, identity.ErrSecurityStateUnavailable) {
		t.Fatalf("late Redis response became a successful session save: %v", err)
	}
}
