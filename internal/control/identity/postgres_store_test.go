package identity

import (
	"context"
	"crypto/sha256"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sokhrym/go-tunnels/migrations"
)

func TestPostgresRecoveryCodeConcurrentConsume(t *testing.T) {
	pool := identityTestPool(t)
	store := NewPostgresStore(pool)
	hash := sha256.Sum256([]byte("single-use-code"))
	if err := store.SaveRecoveryCodes(context.Background(), []RecoveryCode{{Hash: hash, CreatedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}

	var successes atomic.Int32
	var group sync.WaitGroup
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			if store.ConsumeRecoveryCode(context.Background(), hash, time.Now().UTC()) == nil {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful consumes = %d", successes.Load())
	}
}

func TestPostgresSessionRevocation(t *testing.T) {
	pool := identityTestPool(t)
	store := NewPostgresStore(pool)
	hash := sha256.Sum256([]byte("session-token"))
	session := Session{Hash: hash, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := store.SaveSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeSession(context.Background(), hash, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, err := store.Session(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Fatal("session was not revoked")
	}
}

func identityTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = migrations.Up(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(context.Background(), `TRUNCATE admin_sessions, recovery_codes RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	return pool
}
