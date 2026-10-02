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
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/events"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

// App owns the control-plane process and its shutdown order. Dependencies are
// closed in reverse ownership order so consumers stop before their stores.
type App struct {
	stores          *runtimeStores
	server          *http.Server
	metricsServer   *http.Server
	logger          *slog.Logger
	auditPipeline   *events.AuditPipeline
	coordination    *coordination.Handler
	shutdownTimeout time.Duration
}

var _ lifecycle.Component = (*App)(nil)

// New acquires validated stores, builds modules and transfers ownership to Run.
func New(ctx context.Context, cfg config.Control, logger *slog.Logger) (*App, error) {
	return newWithStores(ctx, cfg, logger, openStores)
}

// Migration ownership stays in the dedicated migrate process rather than here or in
// HTTP readiness: only one process should mutate the database schema.
func newWithStores(
	ctx context.Context,
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
	if cfg.Runtime.AuthPerMinute > 5 || cfg.Runtime.OnboardingPerMinute > 10 {
		logger.Warn(
			"authentication quotas exceed safe defaults",
			"auth_per_minute",
			cfg.Runtime.AuthPerMinute,
			"onboarding_per_minute",
			cfg.Runtime.OnboardingPerMinute,
		)
	}

	stores, err := acquire(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	keepStores := false
	defer func() {
		if !keepStores {
			stores.close()
		}
	}()
	httpServer, coordinationHandler, auditPipeline, err := buildHTTP(cfg, logger, stores)
	if err != nil {
		return nil, err
	}
	handler := httpServer.Handler()
	metricsServer := newMetricsServer(cfg)
	keepStores = true
	return &App{
		stores:          stores,
		coordination:    coordinationHandler,
		shutdownTimeout: cfg.Runtime.ShutdownTimeout,
		auditPipeline:   auditPipeline,
		logger:          logger,
		metricsServer:   metricsServer,
		server: &http.Server{
			Addr:              cfg.Server.ListenAddress,
			Handler:           handler,
			ReadHeaderTimeout: cfg.Runtime.HTTPHeaderTimeout,
			ReadTimeout:       cfg.Runtime.HTTPReadTimeout,
			WriteTimeout:      cfg.Runtime.HTTPWriteTimeout,
			IdleTimeout:       cfg.Runtime.HTTPIdleTimeout,
			MaxHeaderBytes:    64 << 10,
		},
	}, nil
}

// Run serves HTTP until the context is cancelled. Shutdown has a bounded
// deadline so a stuck client cannot prevent the process from exiting.
func (a *App) Run(ctx context.Context) error {
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
	components := []lifecycle.Component{
		a.coordination,
		a.auditPipeline,
		lifecycle.Func(func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return nil
			case <-a.auditPipeline.Ready():
			}
			return events.RunOutboxDispatcher(ctx, a.stores.pool, a.auditPipeline, a.logger)
		}),
		lifecycle.Func(
			func(ctx context.Context) error { return serveHTTP(ctx, a.server, listener, a.shutdownTimeout) },
		),
	}
	if a.metricsServer != nil {
		components = append(components, lifecycle.Func(func(ctx context.Context) error {
			return serveHTTP(ctx, a.metricsServer, metricsListener, a.shutdownTimeout)
		}))
	}
	return a.stores.run(ctx, components...)
}
