package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/snapshots"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func snapshotTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	schema := fmt.Sprintf("snapshot_test_%d", time.Now().UnixNano())

	quoted := pgx.Identifier{schema}.Sanitize()

	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()

		t.Fatal(err)
	}

	t.Cleanup(
		func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); admin.Close() },
	)

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}

	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 8

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(pool.Close)

	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}

	return pool
}

func TestPostgresCompareAndAppendSerializesIndependentWriters(t *testing.T) {
	pool := snapshotTestPool(t)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	first, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1},
		private,
		"root",
	)
	if err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup
	var successes atomic.Int32
	errorsSeen := make(chan error, 8)
	start := make(chan struct{})
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()

			<-start

			err := New(pool).Append(context.Background(), "home", 0, nil, first)
			if err == nil {
				successes.Add(1)
			} else {
				errorsSeen <- err
			}
		}()
	}

	close(start)
	group.Wait()
	close(errorsSeen)

	if successes.Load() != 1 {
		t.Fatalf("append winners = %d", successes.Load())
	}

	for err := range errorsSeen {
		if !errors.Is(err, snapshots.ErrSnapshotConflict) {
			t.Fatalf("loser: %v", err)
		}
	}

	service := snapshots.NewService(New(pool), public, "home")

	page, err := service.History(context.Background(), 0, 2)

	if err != nil || len(page) != 1 {
		t.Fatalf("committed history len=%d err=%v", len(page), err)
	}
}

func TestPostgresHistoryScopesNetworkAndRejectsStaleHash(t *testing.T) {
	pool := snapshotTestPool(t)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	repository := New(pool)
	service := snapshots.NewService(repository, public, "home")
	var previous []byte
	for revision := uint64(1); revision <= 4; revision++ {
		envelope, err := snapshot.Sign(
			snapshot.NetworkSnapshot{NetworkID: "home", Revision: revision, PreviousHash: previous},
			private,
			"root",
		)
		if err != nil {
			t.Fatal(err)
		}

		if err := service.Publish(context.Background(), envelope); err != nil {
			t.Fatal(err)
		}

		previous = envelope.Hash
	}

	page, err := service.History(context.Background(), 1, 2)

	if err != nil || len(page) != 2 {
		t.Fatalf("page len=%d err=%v", len(page), err)
	}

	for i, envelope := range page {
		value, _ := snapshot.Decode(envelope)

		if value.Revision != uint64(i+2) {
			t.Fatalf("page revision=%d", value.Revision)
		}
	}

	if _, err := repository.Latest(
		context.Background(),
		"other",
	); !errors.Is(
		err,
		snapshots.ErrSnapshotUnavailable,
	) {
		t.Fatalf("other head: %v", err)
	}

	other, err := repository.History(context.Background(), "other", 0, 2)

	if err != nil || len(other) != 0 {
		t.Fatalf("other history len=%d err=%v", len(other), err)
	}

	next, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 5, PreviousHash: previous},
		private,
		"root",
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := repository.Append(
		context.Background(),
		"home",
		4,
		make([]byte, 32),
		next,
	); !errors.Is(
		err,
		snapshots.ErrSnapshotConflict,
	) {
		t.Fatalf("wrong expected hash: %v", err)
	}

	latest, err := repository.Latest(context.Background(), "home")
	if err != nil {
		t.Fatal(err)
	}

	value, _ := snapshot.Decode(latest)

	if value.Revision != 4 {
		t.Fatalf("failed append advanced head to %d", value.Revision)
	}

	if _, err := pool.Exec(
		context.Background(),
		`DELETE FROM network_snapshots WHERE revision=3`,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := service.History(
		context.Background(),
		1,
		4,
	); !errors.Is(
		err,
		snapshot.ErrRevisionGap,
	) {
		t.Fatalf("gapped persisted history: %v", err)
	}
}
