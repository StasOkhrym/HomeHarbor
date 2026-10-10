// Package relay assembles the stateless encrypted-packet relay runtime.
package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/httpserver"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
	relayruntime "github.com/StasOkhrym/homeharbor/internal/relay"
)

// App owns relay HTTP resources and the in-memory UDP pair. The relay does
// not persist tunnel payloads; restarting it intentionally drops sessions.
type App struct {
	server          *http.Server
	logger          *slog.Logger
	udpListenAddr   string
	ready           *atomic.Bool
	udpPair         *relayruntime.UDPPair
	shutdownTimeout time.Duration
}

var _ lifecycle.Component = (*App)(nil)

// New creates a relay runtime from validated configuration.
func New(cfg config.RelayServer, logger *slog.Logger) (*App, error) {
	return NewWithOptions(cfg, logger, Options{})
}

// Options is the integration boundary for relay configuration owned by the
// parent. TLSConfig must contain the serving certificate (or GetCertificate).
// No proxy header substitutes for the TLS-authenticated control connection.
type Options struct {
	UDPPair   relayruntime.UDPPairConfig
	TLSConfig *tls.Config
}

// NewWithOptions validates the relay without binding listeners or starting workers.
func NewWithOptions(cfg config.RelayServer, logger *slog.Logger, options Options) (*App, error) {
	if cfg.Runtime == (config.Runtime{}) {
		cfg.Runtime = config.DefaultRuntime(true)
	}

	if err := cfg.Runtime.Validate(); err != nil {
		return nil, err
	}

	if options.UDPPair.BindTimeout == 0 {
		options.UDPPair.BindTimeout = cfg.Runtime.RelayBindTimeout
	}

	if options.UDPPair.IdleTimeout == 0 {
		options.UDPPair.IdleTimeout = cfg.Runtime.RelayIdleTimeout
	}

	if options.UDPPair.MaxPeers == 0 {
		options.UDPPair.MaxPeers = cfg.Runtime.RelayMaxPeers
	}

	if options.UDPPair.MaxPeersPerDevice == 0 {
		options.UDPPair.MaxPeersPerDevice = cfg.Runtime.RelayMaxPeersPerDevice
	}

	if options.UDPPair.MaxAdmissions == 0 {
		options.UDPPair.MaxAdmissions = cfg.Runtime.RelayMaxAdmissions
	}

	if logger == nil {
		logger = slog.Default()
	}

	ready := &atomic.Bool{}
	mux := http.NewServeMux()
	tickets := relayruntime.TicketIssuer{Key: []byte(cfg.Security.TicketKey)}

	udpAddress, err := net.ResolveUDPAddr("udp", cfg.Server.UDPListenAddress)
	if err != nil {
		return nil, fmt.Errorf("configure relay UDP address: %w", err)
	}

	if options.UDPPair.ListenIP == nil {
		options.UDPPair.ListenIP = udpAddress.IP
	}

	if options.UDPPair.PortMin == 0 && options.UDPPair.PortMax == 0 && udpAddress.Port != 0 {
		options.UDPPair.PortMin = udpAddress.Port
		options.UDPPair.PortMax = min(udpAddress.Port+1023, 65535)
	}

	port := udpAddress.Port
	if options.UDPPair.PortMin != 0 {
		port = options.UDPPair.PortMin
	}

	host := ""
	if options.UDPPair.ListenIP != nil {
		host = options.UDPPair.ListenIP.String()
	}

	udpListenAddr := net.JoinHostPort(host, strconv.Itoa(port))

	udpPair, err := relayruntime.NewUDPPair(tickets, options.UDPPair)
	if err != nil {
		return nil, fmt.Errorf("configure relay UDP: %w", err)
	}

	if udpPair != nil {
		mux.Handle("/relay/udp", udpPair)
	}

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
		logger:          logger,
		udpListenAddr:   udpListenAddr,
		ready:           ready,
		udpPair:         udpPair,
		shutdownTimeout: cfg.Runtime.ShutdownTimeout,
		server: &http.Server{
			TLSConfig:         options.TLSConfig,
			Addr:              cfg.Server.ListenAddress,
			Handler:           mux,
			ReadHeaderTimeout: cfg.Runtime.HTTPHeaderTimeout,
			ReadTimeout:       cfg.Runtime.HTTPReadTimeout,
			WriteTimeout:      cfg.Runtime.HTTPWriteTimeout,
			IdleTimeout:       cfg.Runtime.HTTPIdleTimeout,
			MaxHeaderBytes:    64 << 10,
		},
	}, nil
}

// Run serves the relay until ctx is cancelled. The UDP pair owner closes
// and joins upgraded WebSocket sessions; HTTP joins ordinary handlers.
func (a *App) Run(ctx context.Context) error {
	defer func() { _ = a.udpPair.Close() }()

	tcpListener, err := net.Listen("tcp", a.server.Addr)
	if err != nil {
		return fmt.Errorf("listen relay HTTP: %w", err)
	}

	udpAddress, err := net.ResolveUDPAddr("udp", a.udpListenAddr)
	if err != nil {
		_ = tcpListener.Close()
		return err
	}

	udpConnection, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		_ = tcpListener.Close()
		return err
	}

	return a.runWithListeners(ctx, tcpListener, udpConnection)
}

// runWithListeners owns both already-bound sockets. Keeping binding outside
// this lifecycle helper lets tests hold exact ephemeral endpoints while still
// exercising the same readiness, shutdown, and UDP relay path as production.
func (a *App) runWithListeners(
	ctx context.Context,
	tcpListener net.Listener,
	udpConnection *net.UDPConn,
) error {
	if tcpListener == nil || udpConnection == nil {
		if tcpListener != nil {
			_ = tcpListener.Close()
		}

		if udpConnection != nil {
			_ = udpConnection.Close()
		}

		return errors.New("relay listeners are required")
	}
	defer func() { _ = tcpListener.Close() }()
	defer func() { _ = udpConnection.Close() }()
	defer func() { _ = a.udpPair.Close() }()

	if err := a.udpPair.AdoptListener(udpConnection); err != nil {
		return err
	}

	if a.server.TLSConfig != nil {
		tcpListener = tls.NewListener(tcpListener, a.server.TLSConfig.Clone())
	}

	a.ready.Store(true)
	defer a.ready.Store(false)

	return lifecycle.RunEssential(ctx,
		lifecycle.Worker{Name: "http", Component: lifecycle.Func(func(ctx context.Context) error {
			return httpserver.Serve(ctx, a.server, tcpListener, a.shutdownTimeout)
		})},
		lifecycle.Worker{Name: "udp", Component: lifecycle.Func(func(ctx context.Context) error {
			// Close owns upgraded WSS handshakes, which net/http cannot drain.
			stopped := make(chan struct{})
			closed := make(chan struct{})
			go func() {
				defer close(closed)

				select {
				case <-ctx.Done():
					_ = a.udpPair.Close()
				case <-stopped:
				}
			}()

			err := a.udpPair.Run(ctx)
			close(stopped)
			<-closed
			_ = a.udpPair.Close()

			return err
		})},
	)
}
