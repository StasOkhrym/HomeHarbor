package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func main() {
	configPath := flag.String("config", "config/control.toml", "control configuration path")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadDatabase(*configPath)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}
	ctx := context.Background()
	poolConfig, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		logger.Error("parse database configuration", "error", err)
		os.Exit(1)
	}
	if cfg.Password != "" {
		poolConfig.ConnConfig.Password = cfg.Password
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		logger.Error("connect database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := migrations.Up(ctx, pool); err != nil {
		logger.Error("apply migrations", "error", err)
		os.Exit(1)
	}
	logger.Info("migrations complete")
}
