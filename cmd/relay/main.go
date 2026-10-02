package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	relayapp "github.com/StasOkhrym/homeharbor/internal/app/relay"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/relay"
)

func main() {
	path := flag.String("config", "config/relay.toml", "relay configuration path")
	certFile := flag.String(
		"tls-cert",
		os.Getenv("HOMEHARBOR_RELAY_TLS_CERT_FILE"),
		"relay TLS certificate PEM file (required)",
	)
	keyFile := flag.String(
		"tls-key",
		os.Getenv("HOMEHARBOR_RELAY_TLS_KEY_FILE"),
		"relay TLS private key PEM file (required)",
	)
	portMin := flag.Int(
		"udp-port-min",
		0,
		"inclusive UDP v2 range start; default derives from udp_listen_address",
	)
	portMax := flag.Int("udp-port-max", 0, "inclusive UDP v2 range end")
	advertiseHost := flag.String(
		"udp-advertise-host",
		"",
		"public UDP v2 hostname/IP; required behind a proxy or NAT",
	)
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadRelayServer(*path)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	// Explicit flags/environment override TOML references. The private key is
	// still loaded from its file, never serialized into config or log fields.
	if *certFile == "" {
		*certFile = cfg.Security.TLSCertFile
	}
	if *keyFile == "" {
		*keyFile = cfg.Security.TLSKeyFile
	}
	if *portMin == 0 {
		*portMin = cfg.Server.UDPPortMin
	}
	if *portMax == 0 {
		*portMax = cfg.Server.UDPPortMax
	}
	if *advertiseHost == "" {
		*advertiseHost = cfg.Server.UDPAdvertiseHost
	}
	tlsConfig, err := relayTLSConfig(*certFile, *keyFile)
	if err != nil {
		logger.Error("load relay TLS", "error", err)
		os.Exit(1)
	}
	app, err := relayapp.NewWithOptions(
		cfg,
		logger,
		relayapp.Options{
			TLSConfig: tlsConfig,
			UDPV2: relay.UDPPairV2Config{
				PortMin:       *portMin,
				PortMax:       *portMax,
				AdvertiseHost: *advertiseHost,
			},
		},
	)
	if err != nil {
		logger.Error("configure relay", "error", err)
		os.Exit(1)
	}
	logger.Info("relay starting", "address", cfg.Server.ListenAddress)
	if err = app.Run(ctx); err != nil {
		logger.Error("serve relay", "error", err)
		os.Exit(1)
	}
}

func relayTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("relay TLS certificate and key files are required")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
	}, nil
}
