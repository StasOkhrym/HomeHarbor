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
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
	relayruntime "github.com/StasOkhrym/homeharbor/internal/relay"
)

// App owns relay HTTP resources and the in-memory session hub. The relay does
// not persist tunnel payloads; restarting it intentionally drops sessions.
type App struct {
	server          *http.Server
	hub             *relayruntime.Hub
	logger          *slog.Logger
	udpListenAddr   string
	tickets         relayruntime.TicketIssuer
	ready           *atomic.Bool
	udpV2           *relayruntime.UDPPairV2
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
	UDPV2     relayruntime.UDPPairV2Config
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
	if options.UDPV2.BindTimeout == 0 {
		options.UDPV2.BindTimeout = cfg.Runtime.RelayBindTimeout
	}
	if options.UDPV2.IdleTimeout == 0 {
		options.UDPV2.IdleTimeout = cfg.Runtime.RelayIdleTimeout
	}
	if options.UDPV2.MaxPeers == 0 {
		options.UDPV2.MaxPeers = cfg.Runtime.RelayMaxPeers
	}
	if options.UDPV2.MaxPeersPerDevice == 0 {
		options.UDPV2.MaxPeersPerDevice = cfg.Runtime.RelayMaxPeersPerDevice
	}
	if options.UDPV2.MaxAdmissions == 0 {
		options.UDPV2.MaxAdmissions = cfg.Runtime.RelayMaxAdmissions
	}
	if logger == nil {
		logger = slog.Default()
	}
	hub := relayruntime.NewHub()
	ready := &atomic.Bool{}
	mux := http.NewServeMux()
	tickets := relayruntime.TicketIssuer{Key: []byte(cfg.Security.TicketKey)}
	udpAddress, err := net.ResolveUDPAddr("udp", cfg.Server.UDPListenAddress)
	if err != nil {
		return nil, fmt.Errorf("configure relay UDP address: %w", err)
	}
	if options.UDPV2.ListenIP == nil {
		options.UDPV2.ListenIP = udpAddress.IP
	}
	if options.UDPV2.PortMin == 0 && options.UDPV2.PortMax == 0 && udpAddress.Port != 0 {
		options.UDPV2.PortMin = udpAddress.Port
		options.UDPV2.PortMax = min(udpAddress.Port+1023, 65535)
	}
	port := udpAddress.Port
	if options.UDPV2.PortMin != 0 {
		port = options.UDPV2.PortMin
	}
	host := ""
	if options.UDPV2.ListenIP != nil {
		host = options.UDPV2.ListenIP.String()
	}
	udpListenAddr := net.JoinHostPort(host, strconv.Itoa(port))
	udpV2, err := relayruntime.NewUDPPairV2(tickets, options.UDPV2)
	if err != nil {
		return nil, fmt.Errorf("configure relay UDP: %w", err)
	}
	if udpV2 != nil {
		mux.Handle("/relay/udp/v2", udpV2)
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
		hub:             hub,
		logger:          logger,
		udpListenAddr:   udpListenAddr,
		tickets:         relayruntime.TicketIssuer{Key: []byte(cfg.Security.TicketKey)},
		ready:           ready,
		udpV2:           udpV2,
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

// Run serves the relay until ctx is cancelled. Active WebSocket sessions are
// closed by net/http shutdown and clients reconnect using their credentials.
func (a *App) Run(ctx context.Context) error {
	defer func() { _ = a.udpV2.Close() }()
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
	defer func() { _ = a.udpV2.Close() }()
	if err := a.udpV2.AdoptListener(udpConnection); err != nil {
		return err
	}
	if a.server.TLSConfig != nil {
		tcpListener = tls.NewListener(tcpListener, a.server.TLSConfig.Clone())
	}
	a.ready.Store(true)
	defer a.ready.Store(false)
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	serverErr := make(chan error, 2)
	go func() { serverErr <- a.server.Serve(tcpListener) }()
	go func() { serverErr <- a.udpV2.Run(runContext) }()
	var err error
	consumed := 0
	select {
	case err = <-serverErr:
		consumed++
	case <-ctx.Done():
	}
	cancel()
	_ = a.udpV2.Close()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), a.shutdownTimeout)
	defer shutdownCancel()
	if shutdownErr := a.server.Shutdown(shutdownCtx); shutdownErr != nil {
		_ = a.server.Close()
		if err == nil {
			err = shutdownErr
		}
	}
	// Both owners finish before returning. Hijacked WSS handshakes are closed
	// and awaited by UDPv2.Close rather than relying on net/http Shutdown.
	for consumed < 2 {
		result := <-serverErr
		consumed++
		if err == nil && result != nil && !errors.Is(result, http.ErrServerClosed) {
			err = result
		}
	}
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		err = nil
	}
	return err
}
