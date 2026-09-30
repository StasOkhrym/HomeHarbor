// Package relay assembles the stateless encrypted-packet relay runtime.
package relay

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sokhrym/go-tunnels/internal/platform/config"
	"github.com/sokhrym/go-tunnels/internal/platform/lifecycle"
	relayruntime "github.com/sokhrym/go-tunnels/internal/relay"
)

// App owns relay HTTP resources and the in-memory session hub. The relay does
// not persist tunnel payloads; restarting it intentionally drops sessions.
type App struct {
	server        *http.Server
	hub           *relayruntime.Hub
	logger        *slog.Logger
	udpListenAddr string
	tickets       relayruntime.TicketIssuer
	ready         *atomic.Bool
}

var _ lifecycle.Component = (*App)(nil)

// New creates a relay runtime from validated configuration.
func New(cfg config.RelayServer, logger *slog.Logger) *App {
	if logger == nil {
		logger = slog.Default()
	}
	hub := relayruntime.NewHub()
	ready := &atomic.Bool{}
	mux := http.NewServeMux()
	mux.Handle("/relay/v1", relayruntime.WebSocketHandler{
		Hub:     hub,
		Tickets: relayruntime.TicketIssuer{Key: []byte(cfg.Security.TicketKey)},
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("GET /metrics", promhttp.Handler())
	return &App{
		hub:           hub,
		logger:        logger,
		udpListenAddr: cfg.Server.UDPListenAddress,
		tickets:       relayruntime.TicketIssuer{Key: []byte(cfg.Security.TicketKey)},
		ready:         ready,
		server: &http.Server{
			Addr:              cfg.Server.ListenAddress,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

// Run serves the relay until ctx is cancelled. Active WebSocket sessions are
// closed by net/http shutdown and clients reconnect using their credentials.
func (a *App) Run(ctx context.Context) error {
	udpAddress, err := net.ResolveUDPAddr("udp", a.udpListenAddr)
	if err != nil {
		return err
	}
	a.ready.Store(true)
	defer a.ready.Store(false)
	udpConnection, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return err
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	udpRelay := relayruntime.NewUDPPairRelay(udpConnection, a.tickets)
	serverErr := make(chan error, 2)
	go func() { serverErr <- a.server.ListenAndServe() }()
	go func() { serverErr <- udpRelay.Run(runContext) }()
	go func() {
		<-runContext.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			a.logger.Error("shutdown relay server", "error", err)
		}
		_ = udpConnection.Close()
	}()
	err = <-serverErr
	cancel()
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		err = nil
	}
	return err
}
