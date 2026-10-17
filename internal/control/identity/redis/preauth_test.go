package redis

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	redisclient "github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestPreauthRedisOutageDoesNotAdmitProof(t *testing.T) {
	client := redisclient.NewClient(&redisclient.Options{Addr: "127.0.0.1:1"})

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewPreauth(client, "closed", time.Now, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	record := identity.Preauth{
		Hash:        sha256.Sum256([]byte("opaque")),
		AccountID:   "a",
		AuthVersion: 1,
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}

	if err := store.SavePreauth(
		t.Context(),
		record,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatalf("unavailable save: %v", err)
	}

	if _, err := store.ReadPreauth(
		t.Context(),
		record.Hash,
		now,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatalf("unavailable inspection: %v", err)
	}

	if _, err := store.AttemptPreauth(
		t.Context(),
		record.Hash,
		now,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatalf("unavailable attempt: %v", err)
	}

	if _, err := store.ConsumePreauth(
		t.Context(),
		record.Hash,
		now,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatalf("unavailable consumption: %v", err)
	}
}

func TestRedisPreauthAttemptsAndConsumptionAreSharedAndBounded(t *testing.T) {
	endpoint := os.Getenv("TEST_REDIS_URL")
	if endpoint == "" {
		t.Skip("TEST_REDIS_URL required for Redis preauth integration")
	}

	options, err := redisclient.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	client := redisclient.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	otherClient := redisclient.NewClient(options)
	t.Cleanup(func() { _ = otherClient.Close() })
	prefix := "test:preauth:" + uuid.NewString()
	first, err := NewPreauth(client, prefix, time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	second, err := NewPreauth(otherClient, prefix, time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	record := identity.Preauth{
		Hash:        sha256.Sum256([]byte("password-proof")),
		AccountID:   "a",
		AuthVersion: 9007199254740993,
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}

	if err := first.SavePreauth(t.Context(), record); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if err := client.Del(ctx, first.key(record.Hash)).Err(); err != nil {
			t.Error(err)
		}
	})

	if err := second.SavePreauth(
		t.Context(),
		record,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("duplicate replaced proof: %v", err)
	}

	before, err := client.PTTL(t.Context(), first.key(record.Hash)).Result()
	if err != nil {
		t.Fatal(err)
	}

	for range 20 {
		inspected, err := second.ReadPreauth(t.Context(), record.Hash, now)

		if err != nil || inspected.Attempts != 0 || inspected.AuthVersion != 9007199254740993 {
			t.Fatalf("inspection spent/changed proof: %+v %v", inspected, err)
		}
	}

	var attempts atomic.Int32
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			if got, err := second.AttemptPreauth(t.Context(), record.Hash, now); err == nil {
				if got.AccountID != "a" || got.AuthVersion != 9007199254740993 {
					t.Error("password proof identity changed")
				}

				attempts.Add(1)
			} else if !errors.Is(err, identity.ErrInvalidCredential) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if attempts.Load() != 5 {
		t.Fatalf("shared attempts=%d", attempts.Load())
	}

	after, err := client.PTTL(t.Context(), first.key(record.Hash)).Result()

	if err != nil || after <= 0 || after > before {
		t.Fatalf("factor attempts extended password proof: %v %v", after, err)
	}

	var consumed atomic.Int32
	for range 12 {
		group.Go(func() {
			if got, err := first.ConsumePreauth(t.Context(), record.Hash, now); err == nil {
				if got.Attempts != 5 {
					t.Error("consumed wrong proof state")
				}

				consumed.Add(1)
			} else if !errors.Is(err, identity.ErrInvalidCredential) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if consumed.Load() != 1 {
		t.Fatalf("shared completions=%d", consumed.Load())
	}

	if _, err := second.AttemptPreauth(
		t.Context(),
		record.Hash,
		now,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("consumed proof replayed")
	}

	if err := first.SavePreauth(t.Context(), record); err != nil {
		t.Fatal(err)
	}

	if err := client.PExpire(t.Context(), first.key(record.Hash), time.Millisecond).
		Err(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		_, err := second.AttemptPreauth(t.Context(), record.Hash, time.Now().UTC())
		if errors.Is(err, identity.ErrInvalidCredential) {
			break
		}

		if err != nil || time.Now().After(deadline) {
			t.Fatal("expired proof remained admitted", err)
		}
	}
}
