package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/internal/control/coordination"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/control/httpapi"
	"github.com/sokhrym/go-tunnels/internal/control/identity"
	controlnetwork "github.com/sokhrym/go-tunnels/internal/control/network"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	"github.com/sokhrym/go-tunnels/internal/platform/config"
	"github.com/sokhrym/go-tunnels/internal/platform/events"
	"github.com/sokhrym/go-tunnels/migrations"
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
	poolConfig, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		logger.Error("parse database configuration", "error", err)
		os.Exit(1)
	}
	if cfg.Database.Password != "" {
		poolConfig.ConnConfig.Password = cfg.Database.Password
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		logger.Error("connect database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		logger.Error("ping database", "error", err)
		os.Exit(1)
	}
	if err = migrations.Up(ctx, pool); err != nil {
		logger.Error("apply migrations", "error", err)
		os.Exit(1)
	}
	bus := gochannel.NewGoChannel(gochannel.Config{}, watermill.NewSlogLogger(logger))
	defer bus.Close()
	if err = events.ConsumeDeviceAudit(ctx, bus, audit.NewPostgresSink(pool), logger, "device.enrolled", "device.revoked"); err != nil {
		logger.Error("start audit consumer", "error", err)
		os.Exit(1)
	}
	service := devices.NewService(devices.NewPostgresStore(pool), time.Now, nil, devices.WithPublisher(events.NewWatermillPublisher(bus)))
	networkService := controlnetwork.NewService(controlnetwork.NewPostgresStore(pool), time.Now)
	policyService := policy.NewService(policy.NewPostgresStore(pool), policy.Compiler{})
	coordinationHandler := coordination.NewHandler(service, policyService, networkService)
	identityStore := identity.NewPostgresStore(pool)
	identityService := identity.NewService(identityStore, time.Now, nil)
	passkeyService, err := identity.NewPasskeyService(identity.PasskeyConfig{RPID: cfg.Auth.RPID, RPOrigin: cfg.Auth.RPOrigin, EncryptionKey: []byte(cfg.Auth.CeremonyEncryptionKey), CeremonyTTL: cfg.Auth.CeremonyDuration()}, identityStore, time.Now, nil)
	if err != nil {
		logger.Error("configure passkeys", "error", err)
		os.Exit(1)
	}
	auth, err := httpapi.NewBrowserAuth(httpapi.BrowserAuthConfig{Origin: cfg.Auth.RPOrigin, SigningKey: []byte(cfg.Auth.SessionSigningKey), SessionTTL: cfg.Auth.SessionDuration(), Auditor: events.NewIdentityAuditor(audit.NewPostgresSink(pool), time.Now)}, passkeyService, identityService)
	if err != nil {
		logger.Error("configure browser authentication", "error", err)
		os.Exit(1)
	}
	handler := httpapi.NewServer(service, auth, httpapi.WithNetworkService(networkService), httpapi.WithPolicyService(policyService), httpapi.WithCoordinationHandler(coordinationHandler), httpapi.WithMetricsHandler(promhttp.Handler())).Handler()
	server := &http.Server{Addr: cfg.Server.ListenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Info("control listening", "address", cfg.Server.ListenAddress)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("serve control", "error", err)
		os.Exit(1)
	}
}
