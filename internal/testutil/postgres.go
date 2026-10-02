// Package testutil provides isolated fixtures for adapter integration tests.
package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/migrations"
)

// Postgres creates a schema owned only by this test. Cleanup never truncates
// shared tables, so independent adapter suites can run against the same DB.
func Postgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL required")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}

	schema := pgx.Identifier{fmt.Sprintf("gt_test_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()

		t.Fatal(err)
	}

	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}

		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}

	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}

	return pool
}

// Device inserts a durable identity fixture, not a bypass used by runtime code.
func Device(t *testing.T, pool *pgxpool.Pool, id, role string) {
	t.Helper()

	_, err := pool.Exec(
		context.Background(),
		`INSERT INTO devices(id,name,role,status,identity_public_key,wireguard_public_key,created_at) VALUES($1,$1,$2,'active',$1||'-identity',$1||'-wg',now())`,
		id,
		role,
	)
	if err != nil {
		t.Fatal(err)
	}
}
