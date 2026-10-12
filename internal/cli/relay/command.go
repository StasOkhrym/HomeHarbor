// Package relay adapts the encrypted relay runtime to the shared CLI host.
package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	relayapp "github.com/StasOkhrym/homeharbor/internal/app/relay"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	relayruntime "github.com/StasOkhrym/homeharbor/internal/relay"
)

type runner func(context.Context, config.RelayServer, *tls.Config, *slog.Logger) error

// NewCommand builds a fresh relay command without reading config or TLS files.
func NewCommand() *cobra.Command { return newCommand(runRelay) }

func newCommand(run runner) *cobra.Command {
	var configPath, certFile, keyFile, ticketKeyFile, advertiseHost string
	var portMin, portMax int
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Run the HomeHarbor encrypted relay",
		Args:  host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := ctx.Err(); err != nil {
				return err
			}

			flags := make(map[string]string)
			for _, field := range []struct{ flag, key, value string }{
				{"ticket-key-file", "security.ticket_key_file", ticketKeyFile},
				{"tls-cert", "security.tls_cert_file", certFile},
				{"tls-key", "security.tls_key_file", keyFile},
				{"udp-port-min", "server.udp_port_min", fmt.Sprint(portMin)},
				{"udp-port-max", "server.udp_port_max", fmt.Sprint(portMax)},
				{"udp-advertise-host", "server.udp_advertise_host", advertiseHost},
			} {
				if cmd.Flags().Changed(field.flag) {
					flags[field.key] = field.value
				}
			}

			cfg, err := config.LoadRelayServer(config.Sources{File: configPath, Flags: flags})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			if err := ctx.Err(); err != nil {
				return err
			}

			tlsConfig, err := relayTLSConfig(cfg.Security.TLSCertFile, cfg.Security.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("load relay TLS: %w", err)
			}

			if err := ctx.Err(); err != nil {
				return err
			}

			logger := slog.New(slog.NewJSONHandler(cmd.OutOrStdout(), nil))
			if err := run(ctx, cfg, tlsConfig, logger); err != nil {
				return fmt.Errorf("run relay: %w", err)
			}

			return ctx.Err()
		},
	}
	flagSet := cmd.Flags()
	flagSet.StringVar(&configPath, "config", "config/relay.toml", "relay configuration path")
	flagSet.StringVar(&ticketKeyFile, "ticket-key-file", "", "relay ticket signing key file")
	flagSet.StringVar(&certFile, "tls-cert", "", "relay TLS certificate PEM file")
	flagSet.StringVar(&keyFile, "tls-key", "", "relay TLS private key PEM file")
	flagSet.IntVar(
		&portMin,
		"udp-port-min",
		0,
		"inclusive UDP range start; defaults from UDP listen address",
	)
	flagSet.IntVar(&portMax, "udp-port-max", 0, "inclusive UDP range end")
	flagSet.StringVar(
		&advertiseHost,
		"udp-advertise-host",
		"",
		"public UDP hostname/IP behind a proxy or NAT",
	)
	return cmd
}

func runRelay(
	ctx context.Context,
	cfg config.RelayServer,
	tlsConfig *tls.Config,
	logger *slog.Logger,
) error {
	app, err := relayapp.NewWithOptions(cfg, logger, relayapp.Options{
		TLSConfig: tlsConfig,
		UDPPair: relayruntime.UDPPairConfig{
			PortMin:        cfg.Server.UDPPortMin,
			PortMax:        cfg.Server.UDPPortMax,
			AdvertiseHost:  cfg.Server.UDPAdvertiseHost,
			AdvertiseHosts: cfg.Server.UDPAdvertiseHosts,
		},
	})
	if err != nil {
		return fmt.Errorf("configure relay: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	logger.Info("relay starting", "address", cfg.Server.ListenAddress)

	if err := app.Run(ctx); err != nil {
		return fmt.Errorf("serve relay: %w", err)
	}

	return ctx.Err()
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
