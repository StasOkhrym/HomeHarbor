// Package postgres owns disposable PostgreSQL schemas for integration tests.
// It never truncates application tables or mutates a caller's search path.
package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenSchema returns a pool scoped to one uniquely owned schema. The caller
// applies whichever migrations its contract needs; cleanup drops only this schema.
func OpenSchema(t *testing.T) *pgxpool.Pool {
	t.Helper()
	endpoint := os.Getenv("TEST_DATABASE_URL")
	if endpoint == "" {
		t.Skip("TEST_DATABASE_URL is required for PostgreSQL schema integration")
	}

	options, err := pgxpool.ParseConfig(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	options.ConnConfig.ConnectTimeout = 5 * time.Second

	admin, err := pgxpool.NewWithConfig(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(admin.Close)
	schema := "hh_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}

	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("remove owned PostgreSQL test schema: %v", err)
		}
	})

	options, err = pgxpool.ParseConfig(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	options.ConnConfig.ConnectTimeout = 5 * time.Second
	if options.ConnConfig.RuntimeParams == nil {
		options.ConnConfig.RuntimeParams = map[string]string{}
	}

	options.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err = pgxpool.NewWithConfig(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}

	return pool
}
