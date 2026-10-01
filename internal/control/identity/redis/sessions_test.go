package redis

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"github.com/sokhrym/go-tunnels/internal/control/identity"
)

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
	store := NewSessions(client, prefix, time.Now)
	other := NewSessions(secondClient, prefix, time.Now)
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
	store := NewSessions(client, "closed", time.Now)
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
