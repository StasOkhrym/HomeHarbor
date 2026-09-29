package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	controlapp "github.com/sokhrym/go-tunnels/internal/app/control"
	"github.com/sokhrym/go-tunnels/internal/platform/config"
)

func main() {
	configPath := flag.String("config", "config/control.toml", "control configuration path")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	cfg, err := config.LoadControl(*configPath)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	app, err := controlapp.New(ctx, cfg, logger)
	if err != nil {
		logger.Error("create control runtime", "error", err)
		os.Exit(1)
	}
	logger.Info("control listening", "address", cfg.Server.ListenAddress)
	if err = app.Run(ctx); err != nil {
		logger.Error("serve control", "error", err)
		os.Exit(1)
	}
}
