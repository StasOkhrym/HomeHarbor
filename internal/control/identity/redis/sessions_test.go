package redis

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

type delayedSessionHook struct{ remaining time.Duration }

func (*delayedSessionHook) DialHook(next redisclient.DialHook) redisclient.DialHook {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return next(ctx, network, address)
	}
}

func (h *delayedSessionHook) ProcessHook(_ redisclient.ProcessHook) redisclient.ProcessHook {
	return func(ctx context.Context, _ redisclient.Cmder) error {
		deadline, _ := ctx.Deadline()

		h.remaining = time.Until(deadline)
		<-ctx.Done()
		return ctx.Err()
	}
}

func (*delayedSessionHook) ProcessPipelineHook(
	next redisclient.ProcessPipelineHook,
) redisclient.ProcessPipelineHook {
	return next
}

func TestSessionOperationsPropagateConfiguredTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	for _, operation := range []string{"save", "lookup", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			client := redisclient.NewClient(&redisclient.Options{Addr: "127.0.0.1:1"})
			t.Cleanup(func() { _ = client.Close() })
			hook := &delayedSessionHook{}

			client.AddHook(hook)

			store, err := NewSessions(client, "test", time.Now, timeout)
			if err != nil {
				t.Fatal(err)
			}

			now := time.Now()
			session := identity.Session{CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
			switch operation {
			case "save":
				err = store.SaveSession(t.Context(), session)
			case "lookup":
				_, err = store.Session(t.Context(), session.Hash)
			case "revoke":
				err = store.RevokeSession(t.Context(), session.Hash, now)
			}

			if !errors.Is(err, identity.ErrSecurityStateUnavailable) {
				t.Fatalf("deadline became a successful operation: %v", err)
			}
			if hook.remaining <= 0 || hook.remaining > timeout {
				t.Fatalf("operation ignored configured timeout: %v", hook.remaining)
			}
		})
	}
}

func TestSessionConstructorRejectsNonpositiveTimeout(t *testing.T) {
	client := redisclient.NewClient(&redisclient.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = client.Close() })
	for _, timeout := range []time.Duration{0, -time.Second} {
		if store, err := NewSessions(client, "test", nil, timeout); err == nil || store != nil {
			t.Fatalf("nonpositive timeout accepted: %v", timeout)
		}
	}
}

func TestRedisSessionSharedTTLAndRevoke(t *testing.T) {
	endpoint := os.Getenv("TEST_REDIS_URL")
	if endpoint == "" {
		t.Skip("TEST_REDIS_URL is required for Redis integration")
	}

	options, err := redisclient.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	client := redisclient.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	secondClient := redisclient.NewClient(options)
	t.Cleanup(func() { _ = secondClient.Close() })
	prefix := fmt.Sprintf("test:browser:%d", time.Now().UnixNano())

	store := mustSessions(t, client, prefix)

	other := mustSessions(t, secondClient, prefix)

	now := time.Now().UTC()

	hash := sha256.Sum256([]byte("never-store-plaintext"))
	session := identity.Session{Hash: hash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}

	if err := store.SaveSession(t.Context(), session); err != nil {
		t.Fatal(err)
	}

	got, err := other.Session(t.Context(), hash)

	if err != nil || got.Hash != hash || !got.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("shared lookup=%+v error=%v", got, err)
	}

	ttl, err := client.PTTL(t.Context(), store.key(hash)).Result()

	if err != nil || ttl <= 0 || ttl > time.Minute {
		t.Fatalf("TTL=%v error=%v", ttl, err)
	}

	if err := store.SaveSession(t.Context(), session); err == nil {
		t.Fatal("duplicate save replaced a live session")
	}

	if err := other.RevokeSession(t.Context(), hash, now); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Session(t.Context(), hash); !errors.Is(err, identity.ErrInvalidCredential) {
		t.Fatalf("revoked lookup=%v", err)
	}

	if err := store.RevokeSession(t.Context(), hash, now); err != nil {
		t.Fatalf("revoke retry=%v", err)
	}

	// Force expiry in Redis rather than sleeping or using a fake clock; the
	// contract checks that absence cannot become a valid browser session.
	hash = sha256.Sum256([]byte("different-expiring-session"))
	session.Hash = hash

	if err := store.SaveSession(t.Context(), session); err != nil {
		t.Fatal(err)
	}

	if err := client.PExpire(t.Context(), store.key(hash), time.Millisecond).Err(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		_, err := other.Session(t.Context(), hash)
		if errors.Is(err, identity.ErrInvalidCredential) {
			break
		}

		if err != nil || time.Now().After(deadline) {
			t.Fatalf("session did not expire: %v", err)
		}
	}
}

func TestSessionTransportFailureIsUnavailable(t *testing.T) {
	client := redisclient.NewClient(
		&redisclient.Options{
			Addr:        "127.0.0.1:1",
			MaxRetries:  -1,
			DialTimeout: 20 * time.Millisecond,
		},
	)

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	store := mustSessions(t, client, "closed")

	hash := sha256.Sum256([]byte("token"))

	if _, err := store.Session(
		t.Context(),
		hash,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatalf("lookup failure=%v", err)
	}

	if err := store.RevokeSession(
		t.Context(),
		hash,
		time.Now(),
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatalf("revoke failure=%v", err)
	}
}

func mustSessions(t *testing.T, client redisclient.UniversalClient, prefix string) *Sessions {
	t.Helper()

	store, err := NewSessions(client, prefix, time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	return store
}
