package redissecurity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	endpoint := os.Getenv("TEST_REDIS_URL")
	if endpoint == "" {
		t.Skip("TEST_REDIS_URL is required for Redis integration")
	}

	options, err := redis.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })

	if err := client.Ping(t.Context()).Err(); err != nil {
		t.Fatal(err)
	}

	return New(client, fmt.Sprintf("test:%d", time.Now().UnixNano()))
}

func TestRedisChallengeConsumedExactlyOnce(t *testing.T) {
	store := testStore(t)

	if err := store.PutChallenge(
		t.Context(),
		"claim",
		"device-secret",
		[]byte("encrypted-payload"),
		time.Minute,
	); err != nil {
		t.Fatal(err)
	}

	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			value, err := store.ConsumeChallenge(t.Context(), "claim", "device-secret")
			if err == nil {
				if string(value) != "encrypted-payload" {
					t.Error("wrong challenge payload")
				}

				successes.Add(1)
			} else if !errors.Is(err, ErrChallengeMissing) {
				t.Error(err)
			}
		})
	}

	wg.Wait()

	if successes.Load() != 1 {
		t.Fatalf("successful claims=%d", successes.Load())
	}
}

func TestRedisRateLimitSharedAcrossClients(t *testing.T) {
	store := testStore(t)
	other := New(store.client, store.prefix)
	for attempt := range 6 {
		selected := store
		if attempt%2 == 1 {
			selected = other
		}

		allowed, retry, err := selected.Allow(t.Context(), "login", "203.0.113.5", 5, time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		if allowed != (attempt < 5) {
			t.Fatalf("attempt %d allowed=%v", attempt, allowed)
		}
		if retry <= 0 || retry > time.Minute {
			t.Fatalf("retry=%v", retry)
		}
	}
}

func TestRedisFailureDoesNotAllowRequest(t *testing.T) {
	client := redis.NewClient(
		&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 50 * time.Millisecond},
	)
	t.Cleanup(func() { _ = client.Close() })

	allowed, _, err := New(
		client,
		"failure",
	).Allow(context.Background(), "login", "client", 5, time.Minute)

	if err == nil || allowed {
		t.Fatalf("allowed=%v error=%v", allowed, err)
	}
}
