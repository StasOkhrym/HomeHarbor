package migrations

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed *.up.sql
var files embed.FS

func Up(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	// Advisory locks are session-scoped, so all migration statements must use
	// the same acquired connection. This prevents two control processes from
	// both observing an unapplied migration and racing its DDL.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended('go_tunnels:migrations', 0))`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(
			context.Background(),
			`SELECT pg_advisory_unlock(hashtextextended('go_tunnels:migrations', 0))`,
		)
	}()
	if _, err := conn.Exec(
		ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations(name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`,
	); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	entries, err := fs.Glob(files, "*.up.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)
	for _, name := range entries {
		var applied bool
		if err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, name).
			Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, readErr := files.ReadFile(name)
		if readErr != nil {
			return readErr
		}
		// Each file and its ledger entry commit together. A crash can therefore
		// only leave a migration fully applied or ready to retry.
		tx, beginErr := conn.Begin(ctx)
		if beginErr != nil {
			return beginErr
		}
		if _, err = tx.Exec(ctx, string(sql)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES($1)`, name)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if err = tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

// Ready reports whether the schema ledger exists and every embedded migration
// has been committed. Runtime processes use this check for readiness; only the
// dedicated migrate command is allowed to mutate schema state.
func Ready(ctx context.Context, pool *pgxpool.Pool) error {
	var ledgerExists bool

	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).
		Scan(&ledgerExists); err != nil {
		return fmt.Errorf("check migration ledger: %w", err)
	}

	if !ledgerExists {
		return errors.New("migration ledger does not exist")
	}

	names, err := Names()
	if err != nil {
		return err
	}

	for _, name := range names {
		var applied bool

		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, name).
			Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}

		if !applied {
			return fmt.Errorf("migration %s is not applied", name)
		}
	}

	return nil
}

func Names() ([]string, error) {
	entries, err := fs.Glob(files, "*.up.sql")
	if err != nil {
		return nil, err
	}

	sort.Strings(entries)
	return entries, nil
}
