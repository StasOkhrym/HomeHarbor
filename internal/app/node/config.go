package node

import (
	"errors"
	"flag"
	"io"

	"github.com/sokhrym/go-tunnels/internal/platform/config"
)

// Role selects policy ownership; transport configuration is shared by both nodes.
type Role uint8

const (
	Client Role = iota
	Gateway
)

// ParseConfig loads TOML defaults before reapplying explicitly supplied flags.
// Both passes use the same bindings, so newly added flags cannot acquire a
// different precedence in the client and gateway executables.
func ParseConfig(role Role, args []string, output io.Writer) (config.Node, error) {
	if role != Client && role != Gateway {
		return config.Node{}, errors.New("invalid node role")
	}
	cfg := config.Node{}
	cfg.Identity.Name, cfg.Identity.StatePath = "linux-client", "state/client.json"
	cfg.Relay.ListenAddress = "127.0.0.1:51822"
	if role == Gateway {
		cfg.Identity.Name, cfg.Identity.StatePath = "linux-gateway", "state/agent.json"
		cfg.Relay.ListenAddress = "127.0.0.1:51821"
	}
	cfg.Relay.WireGuardAddress = "127.0.0.1:51820"
	cfg.WireGuard.ListenPort = 51820
	cfg.Coordination.NetworkID = "home"
	path, err := parseFlags(&cfg, args, output)
	if err != nil || path == "" {
		return cfg, err
	}
	if role == Gateway {
		cfg, err = config.LoadAgent(path)
	} else {
		cfg, err = config.LoadClient(path)
	}
	if err != nil {
		return config.Node{}, err
	}
	_, err = parseFlags(&cfg, args, io.Discard)
	return cfg, err
}

func parseFlags(cfg *config.Node, args []string, output io.Writer) (string, error) {
	flags := flag.NewFlagSet("node", flag.ContinueOnError)
	flags.SetOutput(output)
	path := flags.String("config", "", "TOML node configuration path")
	flags.StringVar(&cfg.Identity.StatePath, "state", cfg.Identity.StatePath, "private node state file")
	flags.StringVar(&cfg.Identity.ControlURL, "control", cfg.Identity.ControlURL, "control plane URL")
	flags.StringVar(&cfg.Identity.Token, "token", cfg.Identity.Token, "legacy enrollment token; prefer TOML enrollment_token_file")
	flags.BoolVar(&cfg.Identity.Refresh, "refresh", cfg.Identity.Refresh, "rotate the current credential")
	flags.StringVar(&cfg.Identity.Name, "name", cfg.Identity.Name, "device name")
	flags.StringVar(&cfg.Relay.WebSocketURL, "relay", cfg.Relay.WebSocketURL, "authenticated relay control URL")
	flags.StringVar(&cfg.Relay.UDPAddress, "relay-udp", cfg.Relay.UDPAddress, "legacy UDP relay endpoint")
	flags.StringVar(&cfg.Relay.Ticket, "relay-ticket", cfg.Relay.Ticket, "legacy relay ticket; prefer TOML ticket_file")
	flags.StringVar(&cfg.Relay.SessionID, "relay-session", cfg.Relay.SessionID, "relay session ID")
	flags.StringVar(&cfg.Relay.DestinationDevice, "relay-destination", cfg.Relay.DestinationDevice, "destination device ID")
	flags.StringVar(&cfg.Relay.ListenAddress, "bridge-listen", cfg.Relay.ListenAddress, "local relay bridge UDP endpoint")
	flags.StringVar(&cfg.Relay.WireGuardAddress, "wireguard-address", cfg.Relay.WireGuardAddress, "local WireGuard UDP endpoint")
	flags.StringVar(&cfg.Relay.STUNServer, "stun", cfg.Relay.STUNServer, "optional UDP STUN URI")
	flags.StringVar(&cfg.WireGuard.InterfaceName, "wg-interface", cfg.WireGuard.InterfaceName, "Linux WireGuard interface; blank selects bridge-only mode")
	flags.UintVar(&cfg.WireGuard.ListenPort, "wg-port", cfg.WireGuard.ListenPort, "WireGuard listen port")
	flags.StringVar(&cfg.WireGuard.PeerPublicKey, "wg-peer-key", cfg.WireGuard.PeerPublicKey, "peer WireGuard public key")
	flags.StringVar(&cfg.WireGuard.OverlayAddress, "wg-overlay", cfg.WireGuard.OverlayAddress, "overlay CIDR")
	flags.StringVar(&cfg.WireGuard.AllowedPrefixes, "wg-allowed-prefixes", cfg.WireGuard.AllowedPrefixes, "comma-separated peer prefixes")
	flags.StringVar(&cfg.WireGuard.Routes, "wg-routes", cfg.WireGuard.Routes, "comma-separated tunnel routes")
	flags.StringVar(&cfg.Coordination.URL, "coordination", cfg.Coordination.URL, "authenticated coordination WebSocket URL")
	flags.StringVar(&cfg.Coordination.RootPublicKeyFile, "root-public-key", cfg.Coordination.RootPublicKeyFile, "trusted companion root public key file")
	flags.StringVar(&cfg.Coordination.NetworkID, "network-id", cfg.Coordination.NetworkID, "signed network ID")
	flags.StringVar(&cfg.Direct.Candidates, "direct-candidates", cfg.Direct.Candidates, "comma-separated direct UDP candidates")
	flags.StringVar(&cfg.DNS.Link, "dns-link", cfg.DNS.Link, "systemd-resolved link; blank disables host DNS integration")
	flags.BoolVar(&cfg.DNS.EnableForwarding, "enable-forwarding", cfg.DNS.EnableForwarding, "explicitly enable host IP forwarding")
	err := parseNodeFlags(flags, args)
	return *path, err
}

func parseNodeFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional node arguments")
	}
	return nil
}
