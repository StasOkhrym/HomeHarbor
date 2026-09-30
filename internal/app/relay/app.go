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
	udpV2         *relayruntime.UDPPairV2
	initErr       error
}

var _ lifecycle.Component = (*App)(nil)

// New creates a relay runtime from validated configuration.
func New(cfg config.RelayServer, logger *slog.Logger) *App {
	return NewWithOptions(cfg, logger, Options{})
}

// Options is the integration boundary for relay configuration owned by the
// parent. TLSConfig must contain the serving certificate (or GetCertificate).
// No proxy header substitutes for the TLS-authenticated control connection.
type Options struct {
	UDPV2     relayruntime.UDPPairV2Config
	TLSConfig *tls.Config
}

func NewWithOptions(cfg config.RelayServer, logger *slog.Logger, options Options) *App {
	if logger == nil {
		logger = slog.Default()
	}
	hub := relayruntime.NewHub()
	ready := &atomic.Bool{}
	mux := http.NewServeMux()
	tickets := relayruntime.TicketIssuer{Key: []byte(cfg.Security.TicketKey)}
	udpAddress, initErr := net.ResolveUDPAddr("udp", cfg.Server.UDPListenAddress)
	udpListenAddr := cfg.Server.UDPListenAddress
	if initErr == nil {
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
		udpListenAddr = net.JoinHostPort(host, strconv.Itoa(port))
	}
	var udpV2 *relayruntime.UDPPairV2
	if initErr == nil {
		udpV2, initErr = relayruntime.NewUDPPairV2(tickets, options.UDPV2)
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
		hub:           hub,
		logger:        logger,
		udpListenAddr: udpListenAddr,
		tickets:       relayruntime.TicketIssuer{Key: []byte(cfg.Security.TicketKey)},
		ready:         ready,
		udpV2:         udpV2,
		initErr:       initErr,
		server: &http.Server{
			TLSConfig:         options.TLSConfig,
			Addr:              cfg.Server.ListenAddress,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    64 << 10,
		},
	}
}

// Run serves the relay until ctx is cancelled. Active WebSocket sessions are
// closed by net/http shutdown and clients reconnect using their credentials.
func (a *App) Run(ctx context.Context) error {
	if a.initErr != nil {
		return a.initErr
	}
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
func (a *App) runWithListeners(ctx context.Context, tcpListener net.Listener, udpConnection *net.UDPConn) error {
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
	if a.initErr != nil {
		return a.initErr
	}
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
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
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
