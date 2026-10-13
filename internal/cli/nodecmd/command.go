// Package nodecmd binds the common client and gateway flags at the CLI edge.
package nodecmd

import (
	"context"
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

type runner func(context.Context, nodeapp.Role, config.Node) error

var configKeys = map[string]string{
	"state": "node.state_path", "control": "node.control_url", "token": "node.token",
	"ca-file": "node.ca_file",
	"refresh": "node.refresh", "name": "node.name",
	"relay":        "relay.websocket_url",
	"relay-ticket": "relay.ticket", "relay-session": "relay.session_id",
	"relay-destination": "relay.destination_device_id", "bridge-listen": "relay.listen_address",
	"wireguard-address": "relay.wireguard_address",
	"wg-interface":      "wireguard.interface", "wg-port": "wireguard.listen_port",
	"wg-peer-key": "wireguard.peer_public_key", "wg-overlay": "wireguard.overlay_address",
	"wg-allowed-prefixes": "wireguard.allowed_prefixes", "wg-routes": "wireguard.routes",
	"coordination": "coordination.url", "root-public-key": "coordination.root_public_key_file",
	"network-id": "coordination.network_id", "direct-candidates": "direct.candidates",
	"dns-link": "dns.link", "enable-forwarding": "dns.enable_forwarding",
	"native": "native.enabled", "native-overlay": "native.overlay",
	"native-private": "native.private", "native-suffix": "native.suffix",
}

// NewCommand creates an independent Cobra tree without opening files or starting a node.
func NewCommand(role nodeapp.Role) *cobra.Command { return newCommand(role, nodeapp.RunCommand) }

func roleName(role nodeapp.Role) string {
	if role == nodeapp.Gateway {
		return "agent"
	}

	return "client"
}

func newCommand(role nodeapp.Role, run runner) *cobra.Command {
	defaults := config.DefaultClient()
	if role == nodeapp.Gateway {
		defaults = config.DefaultAgent()
	}
	var path string
	cmd := &cobra.Command{
		Use:   roleName(role),
		Short: "Run a HomeHarbor " + roleName(role) + " node",
		Args:  host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			if role != nodeapp.Client && role != nodeapp.Gateway {
				return errors.New("invalid node role")
			}
			changed := make(map[string]string)
			cmd.Flags().Visit(func(flag *pflag.Flag) {
				if key, ok := configKeys[flag.Name]; ok {
					changed[key] = flag.Value.String()
				}
			})
			source := config.Sources{File: path, Flags: changed}
			var cfg config.Node
			var err error
			if role == nodeapp.Gateway {
				cfg, err = config.LoadAgent(source)
			} else {
				cfg, err = config.LoadClient(source)
			}
			if err != nil {
				return err
			}
			return run(cmd.Context(), role, cfg)
		},
	}
	bindFlags(cmd, &defaults, &path)
	if role == nodeapp.Client {
		f := cmd.Flags()
		f.BoolVar(
			&defaults.Native.Enabled,
			"native",
			false,
			"opt into the installed macOS native network helper",
		)
		f.StringVar(
			&defaults.Native.Overlay,
			"native-overlay",
			"",
			"independently provisioned native overlay pool",
		)
		f.StringVar(
			&defaults.Native.Private,
			"native-private",
			"",
			"independently provisioned native private subnet",
		)
		f.StringVar(
			&defaults.Native.Suffix,
			"native-suffix",
			"",
			"independently provisioned native DNS suffix",
		)
	}
	return cmd
}

func bindFlags(cmd *cobra.Command, cfg *config.Node, path *string) {
	f := cmd.Flags()
	f.StringVar(path, "config", "", "TOML node configuration path")
	f.StringVar(&cfg.Identity.StatePath, "state", cfg.Identity.StatePath, "private node state file")
	f.StringVar(&cfg.Identity.ControlURL, "control", cfg.Identity.ControlURL, "control plane URL")
	f.StringVar(
		&cfg.Identity.CAFile,
		"ca-file",
		cfg.Identity.CAFile,
		"explicit PEM CA for control and relay TLS",
	)
	f.StringVar(
		&cfg.Identity.Token,
		"token",
		cfg.Identity.Token,
		"legacy enrollment token; prefer TOML enrollment_token_file",
	)
	f.BoolVar(
		&cfg.Identity.Refresh,
		"refresh",
		cfg.Identity.Refresh,
		"rotate the current credential",
	)
	f.StringVar(&cfg.Identity.Name, "name", cfg.Identity.Name, "device name")
	f.StringVar(
		&cfg.Relay.WebSocketURL,
		"relay",
		cfg.Relay.WebSocketURL,
		"authenticated relay control URL",
	)
	f.StringVar(
		&cfg.Relay.Ticket,
		"relay-ticket",
		cfg.Relay.Ticket,
		"legacy relay ticket; prefer TOML ticket_file",
	)
	f.StringVar(&cfg.Relay.SessionID, "relay-session", cfg.Relay.SessionID, "relay session ID")
	f.StringVar(
		&cfg.Relay.DestinationDevice,
		"relay-destination",
		cfg.Relay.DestinationDevice,
		"destination device ID",
	)
	f.StringVar(
		&cfg.Relay.ListenAddress,
		"bridge-listen",
		cfg.Relay.ListenAddress,
		"local relay bridge UDP endpoint",
	)
	f.StringVar(
		&cfg.Relay.WireGuardAddress,
		"wireguard-address",
		cfg.Relay.WireGuardAddress,
		"local WireGuard UDP endpoint",
	)
	f.StringVar(
		&cfg.WireGuard.InterfaceName,
		"wg-interface",
		cfg.WireGuard.InterfaceName,
		"Linux WireGuard interface; blank selects bridge-only mode",
	)
	f.UintVar(
		&cfg.WireGuard.ListenPort,
		"wg-port",
		cfg.WireGuard.ListenPort,
		"WireGuard listen port",
	)
	f.StringVar(
		&cfg.WireGuard.PeerPublicKey,
		"wg-peer-key",
		cfg.WireGuard.PeerPublicKey,
		"peer WireGuard public key",
	)
	f.StringVar(
		&cfg.WireGuard.OverlayAddress,
		"wg-overlay",
		cfg.WireGuard.OverlayAddress,
		"overlay CIDR",
	)
	f.StringVar(
		&cfg.WireGuard.AllowedPrefixes,
		"wg-allowed-prefixes",
		cfg.WireGuard.AllowedPrefixes,
		"comma-separated peer prefixes",
	)
	f.StringVar(
		&cfg.WireGuard.Routes,
		"wg-routes",
		cfg.WireGuard.Routes,
		"comma-separated tunnel routes",
	)
	f.StringVar(
		&cfg.Coordination.URL,
		"coordination",
		cfg.Coordination.URL,
		"authenticated coordination WebSocket URL",
	)
	f.StringVar(
		&cfg.Coordination.RootPublicKeyFile,
		"root-public-key",
		cfg.Coordination.RootPublicKeyFile,
		"trusted companion root public key file",
	)
	f.StringVar(
		&cfg.Coordination.NetworkID,
		"network-id",
		cfg.Coordination.NetworkID,
		"signed network ID",
	)
	f.StringVar(
		&cfg.Direct.Candidates,
		"direct-candidates",
		cfg.Direct.Candidates,
		"comma-separated direct UDP candidates",
	)
	f.StringVar(
		&cfg.DNS.Link,
		"dns-link",
		cfg.DNS.Link,
		"systemd-resolved link; blank disables host DNS integration",
	)
	f.BoolVar(
		&cfg.DNS.EnableForwarding,
		"enable-forwarding",
		cfg.DNS.EnableForwarding,
		"explicitly enable host IP forwarding",
	)
}
