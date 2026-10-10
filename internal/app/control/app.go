// Package control assembles the control-plane runtime. Domain modules expose
// narrow interfaces; this package is the only place that wires concrete
// PostgreSQL, Watermill, HTTP, and observability implementations together.
package control

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/coordination"
	"github.com/StasOkhrym/homeharbor/internal/control/events"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

// App owns the control-plane process and its shutdown order. Dependencies are
// closed in reverse ownership order so consumers stop before their stores.
type App struct {
	cfg             config.Control
	acquire         func(context.Context, config.Control, *slog.Logger) (*runtimeStores, error)
	stores          *runtimeStores
	server          *http.Server
	metricsServer   *http.Server
	logger          *slog.Logger
	auditDispatcher *events.Dispatcher
	coordination    *coordination.Handler
	shutdownTimeout time.Duration
}

var _ lifecycle.Component = (*App)(nil)

// New validates configuration without acquiring resources. Run owns acquisition.
func New(ctx context.Context, cfg config.Control, logger *slog.Logger) (*App, error) {
	return newWithStores(ctx, cfg, logger, openStores)
}

// Migration ownership stays in the dedicated migrate process rather than here or in
// HTTP readiness: only one process should mutate the database schema.
func newWithStores(
	_ context.Context,
	cfg config.Control,
	logger *slog.Logger,
	acquire func(context.Context, config.Control, *slog.Logger) (*runtimeStores, error),
) (*App, error) {
	if cfg.Runtime == (config.Runtime{}) {
		cfg.Runtime = config.DefaultRuntime(false)
	}
	if err := cfg.Runtime.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &App{cfg: cfg, acquire: acquire, logger: logger}, nil
}

// assemble acquires stores and builds consumers within the Run ownership scope.
func (a *App) assemble(ctx context.Context) error {
	cfg, logger := a.cfg, a.logger
	if cfg.Runtime.AuthPerMinute > 5 || cfg.Runtime.OnboardingPerMinute > 10 {
		logger.Warn(
			"authentication quotas exceed safe defaults",
			"auth_per_minute",
			cfg.Runtime.AuthPerMinute,
			"onboarding_per_minute",
			cfg.Runtime.OnboardingPerMinute,
		)
	}

	stores, err := a.acquire(ctx, cfg, logger)
	if err != nil {
		return err
	}
	a.stores = stores
	keepStores := false
	defer func() {
		if !keepStores {
			stores.close()
		}
	}()
	httpServer, coordinationHandler, auditDispatcher, err := buildHTTP(cfg, logger, stores)
	if err != nil {
		return err
	}
	a.coordination = coordinationHandler
	a.auditDispatcher = auditDispatcher
	a.shutdownTimeout = cfg.Runtime.ShutdownTimeout
	a.metricsServer = newMetricsServer(cfg)
	a.server = &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           httpServer.Handler(),
		ReadHeaderTimeout: cfg.Runtime.HTTPHeaderTimeout,
		ReadTimeout:       cfg.Runtime.HTTPReadTimeout,
		WriteTimeout:      cfg.Runtime.HTTPWriteTimeout,
		IdleTimeout:       cfg.Runtime.HTTPIdleTimeout,
		MaxHeaderBytes:    64 << 10,
	}
	keepStores = true
	return nil
}

// Run owns acquisition and joins workers before releasing their stores.
// The CLI host owns hard termination if a handler cannot finish draining.
func (a *App) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	if err := a.assemble(ctx); err != nil {
		return err
	}
	// Run owns every dependency even if listener creation fails. Workers stop
	// before stores close; a deferred cleanup cannot race a still-running sink.
	defer a.stores.close()
	listener, err := net.Listen("tcp", a.server.Addr)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	var metricsListener net.Listener
	if a.metricsServer != nil {
		metricsListener, err = net.Listen("tcp", a.metricsServer.Addr)
		if err != nil {
			return err
		}
		defer func() { _ = metricsListener.Close() }()
	}
	workers := []lifecycle.Worker{
		{Name: "coordination", Component: a.coordination},
		{Name: "outbox", Component: a.auditDispatcher},
		{Name: "http", Component: lifecycle.Func(
			func(ctx context.Context) error { return serveHTTP(ctx, a.server, listener, a.shutdownTimeout) },
		)},
	}
	if a.metricsServer != nil {
		workers = append(
			workers,
			lifecycle.Worker{
				Name: "metrics",
				Component: lifecycle.Func(func(ctx context.Context) error {
					return serveHTTP(ctx, a.metricsServer, metricsListener, a.shutdownTimeout)
				}),
			},
		)
	}
	return lifecycle.RunEssential(ctx, workers...)
}
