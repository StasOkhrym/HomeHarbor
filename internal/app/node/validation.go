package node

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/agent/dns"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

// validateRuntime performs no enrollment, identity writes or endpoint discovery.
// Even fields used late in startup are checked before persistent side effects.
func validateRuntime(role Role, cfg config.Node) error {
	if err := cfg.Runtime.Validate(); err != nil {
		return err
	}
	if role != Client && role != Gateway {
		return errors.New("invalid node role")
	}
	if cfg.Native.Enabled {
		if err := validateNativeRuntime(role, cfg, runtime.GOOS); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.Identity.StatePath) == "" {
		return errors.New("state path is required")
	}
	if cfg.WireGuard.ListenPort > 65535 {
		return errors.New("WireGuard port exceeds 65535")
	}
	if err := validateNodeURL(cfg.Identity.ControlURL, "control", "http", "https"); err != nil {
		return err
	}
	if err := validateNodeURL(cfg.Coordination.URL, "coordination", "ws", "wss"); err != nil {
		return err
	}
	if err := validateNodeURL(cfg.Relay.WebSocketURL, "relay", "ws", "wss"); err != nil {
		return err
	}
	if cfg.Identity.CAFile != "" {
		for _, endpoint := range []struct {
			value, scheme string
		}{
			{cfg.Identity.ControlURL, "https"},
			{cfg.Coordination.URL, "wss"},
			{cfg.Relay.WebSocketURL, "wss"},
		} {
			if endpoint.value == "" {
				continue
			}
			parsed, _ := url.Parse(endpoint.value)
			if parsed.Scheme != endpoint.scheme {
				return errors.New("explicit CA requires HTTPS control and WSS connections")
			}
		}
	}
	if _, err := node.ParseDirectCandidates(cfg.Direct.Candidates); err != nil {
		return err
	}
	for _, prefixes := range []string{cfg.WireGuard.AllowedPrefixes, cfg.WireGuard.Routes} {
		if _, err := node.ParsePrefixList(prefixes); err != nil {
			return err
		}
	}
	if cfg.WireGuard.PeerPublicKey != "" {
		if _, err := wgtypes.ParseKey(cfg.WireGuard.PeerPublicKey); err != nil {
			return errors.New("invalid peer WireGuard public key")
		}
	}
	if cfg.WireGuard.OverlayAddress != "" {
		if _, err := netip.ParsePrefix(cfg.WireGuard.OverlayAddress); err != nil {
			return errors.New("invalid overlay address")
		}
	}
	kernel := cfg.WireGuard.InterfaceName != "" || cfg.Coordination.URL != ""
	if kernel {
		if (!cfg.Native.Enabled && cfg.WireGuard.InterfaceName == "") ||
			cfg.Coordination.URL == "" ||
			cfg.Coordination.RootPublicKeyFile == "" ||
			cfg.Coordination.NetworkID == "" {
			return errors.New(
				"kernel node requires interface, signed coordination, network and root key",
			)
		}
		// Root verification is read-only; a malformed trust anchor must never
		// cause a new device identity to be written or enrolled.
		if _, err := node.LoadPublicKeyFile(cfg.Coordination.RootPublicKeyFile); err != nil {
			return err
		}
		if !cfg.Native.Enabled {
			if _, err := dns.NewManager(cfg.WireGuard.InterfaceName); err != nil {
				return err
			}
		}
	}
	if cfg.DNS.Link != "" {
		if _, err := dns.NewManager(cfg.DNS.Link); err != nil {
			return err
		}
	}
	relayEnabled := cfg.Relay.WebSocketURL != "" || cfg.Relay.Ticket != ""
	if !relayEnabled {
		return nil
	}
	if strings.TrimSpace(cfg.Relay.SessionID) == "" ||
		strings.TrimSpace(cfg.Relay.DestinationDevice) == "" {
		return errors.New("relay session and destination are required")
	}
	if cfg.Relay.Ticket != "" && cfg.Relay.WebSocketURL == "" {
		return errors.New("authenticated relay control URL is required with a ticket")
	}
	if cfg.Relay.Ticket == "" && cfg.Identity.ControlURL == "" {
		return errors.New("control URL is required to obtain relay admission")
	}
	if err := protocol.ValidateRelayControlURL(cfg.Relay.WebSocketURL); err != nil {
		return err
	}
	addresses := []string{cfg.Relay.ListenAddress, cfg.Relay.WireGuardAddress}
	for _, address := range addresses {
		// Syntax only: hostname resolution belongs to runtime and can fail
		// transiently without turning construction into network discovery.
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return errors.New("invalid relay UDP endpoint")
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return errors.New("invalid relay UDP port")
		}
	}
	if kernel && !cfg.Native.Enabled &&
		(cfg.WireGuard.ListenPort == 0 || cfg.WireGuard.PeerPublicKey == "" ||
			cfg.WireGuard.OverlayAddress == "") {
		return errors.New("kernel relay requires listen port, peer key and overlay address")
	}
	return nil
}

func validateNodeURL(value, label string, schemes ...string) error {
	if value == "" {
		return nil
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("invalid %s URL", label)
	}

	for _, scheme := range schemes {
		if parsed.Scheme == scheme {
			return nil
		}
	}

	return fmt.Errorf("invalid %s URL scheme", label)
}
