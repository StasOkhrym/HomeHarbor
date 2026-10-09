// Package migrate adapts the one-shot schema migration to the shared CLI host.
package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/migrations"
)

type migrationSession interface {
	Apply(context.Context) error
	Close()
}

type postgresSession struct{ pool *pgxpool.Pool }

func (s *postgresSession) Apply(ctx context.Context) error { return migrations.Up(ctx, s.pool) }
func (s *postgresSession) Close()                          { s.pool.Close() }

func openPostgres(ctx context.Context, cfg config.Database) (migrationSession, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}

	if cfg.Password != "" {
		poolConfig.ConnConfig.Password = cfg.Password
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	return &postgresSession{pool: pool}, nil
}

// NewCommand returns an independent migration command with no startup effects.
func NewCommand() *cobra.Command { return newCommand(openPostgres) }

func newCommand(
	open func(context.Context, config.Database) (migrationSession, error),
) *cobra.Command {
	var configPath string
	command := &cobra.Command{
		Use:   "migrate",
		Short: "Apply HomeHarbor database migrations",
		Args:  host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := ctx.Err(); err != nil {
				return err
			}
			cfg, err := config.LoadDatabase(config.Sources{File: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			session, err := open(ctx, cfg)
			if err != nil {
				return err
			}
			if session == nil {
				return errors.New("migration session is unavailable")
			}
			defer session.Close()
			if err := session.Apply(ctx); err != nil {
				return fmt.Errorf("apply migrations: %w", err)
			}
			cmd.Println("migrations complete")
			return nil
		},
	}
	command.Flags().
		StringVar(&configPath, "config", "config/control.toml", "control configuration path")
	return command
}
