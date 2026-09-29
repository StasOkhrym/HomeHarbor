package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	relayapp "github.com/sokhrym/go-tunnels/internal/app/relay"
	"github.com/sokhrym/go-tunnels/internal/platform/config"
)

func main() {
	path := flag.String("config", "config/relay.toml", "relay configuration path")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadRelayServer(*path)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	app := relayapp.New(cfg, logger)
	logger.Info("relay listening", "address", cfg.Server.ListenAddress)
	if err = app.Run(ctx); err != nil {
		logger.Error("serve relay", "error", err)
		os.Exit(1)
	}
}
