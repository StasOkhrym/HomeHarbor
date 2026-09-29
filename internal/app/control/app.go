// Package control assembles the control-plane runtime. Domain modules expose
// narrow interfaces; this package is the only place that wires concrete
// PostgreSQL, Watermill, HTTP, and observability implementations together.
package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
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
	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	controlnetwork "github.com/sokhrym/go-tunnels/internal/control/routes"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
	controlsnapshots "github.com/sokhrym/go-tunnels/internal/control/snapshots"
	"github.com/sokhrym/go-tunnels/internal/platform/config"
	"github.com/sokhrym/go-tunnels/internal/platform/events"
	"github.com/sokhrym/go-tunnels/internal/platform/lifecycle"
	"github.com/sokhrym/go-tunnels/migrations"
)

// App owns the control-plane process and its shutdown order. Dependencies are
// closed in reverse ownership order so consumers stop before their stores.
type App struct {
	server *http.Server
	pool   *pgxpool.Pool
	bus    *gochannel.GoChannel
	logger *slog.Logger
}

var _ lifecycle.Component = (*App)(nil)

// New validates dependencies, runs migrations, and builds the HTTP runtime.
// Migration ownership intentionally stays here rather than in HTTP readiness:
// only one dedicated control process should mutate the database schema.
func New(ctx context.Context, cfg config.Control, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	poolConfig, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return nil, errors.Join(errors.New("parse database configuration"), err)
	}
	if cfg.Database.Password != "" {
		poolConfig.ConnConfig.Password = cfg.Database.Password
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.Join(errors.New("connect database"), err)
	}
	closePool := func(err error) (*App, error) {
		pool.Close()
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return closePool(errors.Join(errors.New("ping database"), err))
	}
	if err := migrations.Up(ctx, pool); err != nil {
		return closePool(errors.Join(errors.New("apply migrations"), err))
	}

	bus := gochannel.NewGoChannel(gochannel.Config{}, watermill.NewSlogLogger(logger))
	closeBusAndPool := func(err error) (*App, error) {
		_ = bus.Close()
		pool.Close()
		return nil, err
	}
	if err := events.ConsumeDeviceAudit(ctx, bus, audit.NewPostgresSink(pool), logger, "device.enrolled", "device.revoked"); err != nil {
		return closeBusAndPool(errors.Join(errors.New("start audit consumer"), err))
	}

	deviceService := devices.NewService(devices.NewPostgresStore(pool), time.Now, nil, devices.WithPublisher(events.NewWatermillPublisher(bus)))
	networkService := controlnetwork.NewService(controlnetwork.NewPostgresStore(pool), time.Now)
	policyService := policy.NewService(policy.NewPostgresStore(pool), policy.Compiler{})
	serviceCatalog := controlservices.NewService(controlservices.NewPostgresStore(pool), time.Now)
	coordinationHandler := coordination.NewHandler(deviceService, nil, []string{cfg.Auth.RPOrigin})
	var signedSnapshots *controlsnapshots.Service
	identityStore := identity.NewPostgresStore(pool)
	identityService := identity.NewService(identityStore, time.Now, nil)
	passkeyService, err := identity.NewPasskeyService(identity.PasskeyConfig{
		RPID:          cfg.Auth.RPID,
		RPOrigin:      cfg.Auth.RPOrigin,
		EncryptionKey: []byte(cfg.Auth.CeremonyEncryptionKey),
		CeremonyTTL:   cfg.Auth.CeremonyDuration(),
	}, identityStore, time.Now, nil)
	if err != nil {
		return closeBusAndPool(errors.Join(errors.New("configure passkeys"), err))
	}
	auth, err := httpapi.NewBrowserAuth(httpapi.BrowserAuthConfig{
		Origin:     cfg.Auth.RPOrigin,
		SigningKey: []byte(cfg.Auth.SessionSigningKey),
		SessionTTL: cfg.Auth.SessionDuration(),
		Auditor:    events.NewIdentityAuditor(audit.NewPostgresSink(pool), time.Now),
	}, passkeyService, identityService)
	if err != nil {
		return closeBusAndPool(errors.Join(errors.New("configure browser authentication"), err))
	}

	serverOptions := []httpapi.ServerOption{
		httpapi.WithNetworkService(networkService),
		httpapi.WithPolicyService(policyService),
		httpapi.WithServiceCatalog(serviceCatalog),
		httpapi.WithMetricsHandler(promhttp.Handler()),
		httpapi.WithReadiness(pool.Ping),
	}
	trustedProxyCIDRs := make([]netip.Prefix, 0, len(cfg.Security.TrustedProxyCIDRs))
	for _, value := range cfg.Security.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return closeBusAndPool(errors.Join(errors.New("parse trusted proxy CIDR"), err))
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, prefix)
	}
	serverOptions = append(serverOptions, httpapi.WithTrustedProxyCIDRs(trustedProxyCIDRs))
	if cfg.Security.RootPublicKeyFile != "" {
		rootPublic, err := loadRootPublicKey(cfg.Security.RootPublicKeyFile)
		if err != nil {
			return closeBusAndPool(errors.Join(errors.New("load trusted companion root key"), err))
		}
		if strings.TrimSpace(cfg.Networking.NetworkID) == "" {
			return closeBusAndPool(errors.New("networking.network_id is required when invite verification is enabled"))
		}
		signedSnapshots = controlsnapshots.NewService(controlsnapshots.NewPostgresStore(pool), rootPublic, cfg.Networking.NetworkID)
		serverOptions = append(serverOptions,
			httpapi.WithInviteService(controlinvites.NewService(controlinvites.NewPostgresStore(pool), rootPublic, cfg.Networking.NetworkID, time.Now)),
			httpapi.WithSnapshotService(signedSnapshots),
		)
		coordinationHandler = coordination.NewHandler(deviceService, signedSnapshots, []string{cfg.Auth.RPOrigin})
	}
	serverOptions = append(serverOptions, httpapi.WithCoordinationHandler(coordinationHandler))
	handler := httpapi.NewServer(
		deviceService,
		auth,
		serverOptions...,
	).Handler()

	return &App{
		pool:   pool,
		bus:    bus,
		logger: logger,
		server: &http.Server{
			Addr:              cfg.Server.ListenAddress,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}, nil
}

func loadRootPublicKey(path string) (ed25519.PublicKey, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value = []byte(strings.TrimSpace(string(value)))
	if decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(value)); decodeErr == nil {
		value = decoded
	}
	if len(value) != ed25519.PublicKeySize {
		return nil, errors.New("trusted companion root public key must be 32 raw or base64url bytes")
	}
	return ed25519.PublicKey(append([]byte(nil), value...)), nil
}

// Run serves HTTP until the context is cancelled. Shutdown has a bounded
// deadline so a stuck client cannot prevent the process from exiting.
func (a *App) Run(ctx context.Context) error {
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- a.server.ListenAndServe()
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			a.logger.Error("shutdown control server", "error", err)
		}
	}()

	err := <-serverErr
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		err = nil
	}
	_ = a.bus.Close()
	a.pool.Close()
	return err
}
