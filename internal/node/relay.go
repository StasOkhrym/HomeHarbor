package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sokhrym/go-tunnels/internal/relay"
	"github.com/sokhrym/go-tunnels/internal/tunnel"
)

// RelayBridgeConfig binds a node's local WireGuard UDP socket to an encrypted
// relay path. The bridge itself does not know WireGuard keys or policy; those
// concerns remain owned by the tunnel and gateway layers.
type RelayBridgeConfig struct {
	RelayURL            string
	Ticket              string
	SessionID           string
	DeviceID            string
	DestinationDeviceID string
	ListenAddress       string
	WireGuardAddress    string
}

// KernelRelayConfig extends the bridge with the Linux kernel WireGuard and
// route lifecycle. A blank InterfaceName deliberately selects bridge-only
// mode, which is useful for protocol tests and non-Linux development.
type KernelRelayConfig struct {
	RelayBridgeConfig
	InterfaceName   string
	PrivateKey      string
	ListenPort      uint16
	OverlayAddress  string
	PeerPublicKey   string
	AllowedPrefixes []netip.Prefix
	Routes          []netip.Prefix
}

// ParsePrefixList parses the comma-separated route form used by the thin CLI
// entrypoints. Empty input means no routes, which is safer than guessing a
// broad private network from a device's local address.
func ParsePrefixList(value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("parse prefix %q: %w", part, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// RunRelayBridge owns the bridge until control cancellation or a transport
// failure. Callers should recreate it after credential/session renewal rather
// than mutating a live bridge's ticket.
func RunRelayBridge(ctx context.Context, cfg RelayBridgeConfig) error {
	listenAddress, err := net.ResolveUDPAddr("udp", cfg.ListenAddress)
	if err != nil {
		return errors.New("invalid relay bridge listen address: " + err.Error())
	}
	wireGuardAddress, err := net.ResolveUDPAddr("udp", cfg.WireGuardAddress)
	if err != nil {
		return errors.New("invalid WireGuard UDP address: " + err.Error())
	}
	bridge, err := relay.NewBridge(relay.BridgeConfig{
		RelayURL:            cfg.RelayURL,
		Ticket:              cfg.Ticket,
		SessionID:           cfg.SessionID,
		DeviceID:            cfg.DeviceID,
		DestinationDeviceID: cfg.DestinationDeviceID,
		ListenAddress:       listenAddress,
		WireGuardAddress:    wireGuardAddress,
	})
	if err != nil {
		return err
	}
	return bridge.Run(ctx)
}

// RunKernelRelay reconciles a Linux interface before opening the relay
// transport. WireGuard receives the bridge's loopback UDP address as its peer
// endpoint; the bridge then carries the already-encrypted datagrams remotely.
func RunKernelRelay(ctx context.Context, cfg KernelRelayConfig) error {
	if cfg.InterfaceName == "" || cfg.PrivateKey == "" || cfg.PeerPublicKey == "" || cfg.OverlayAddress == "" || cfg.ListenPort == 0 {
		return errors.New("kernel relay interface, keys, overlay address, and listen port are required")
	}
	listenAddress, err := net.ResolveUDPAddr("udp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("invalid relay bridge listen address: %w", err)
	}
	wireGuardAddress, err := net.ResolveUDPAddr("udp", cfg.WireGuardAddress)
	if err != nil {
		return fmt.Errorf("invalid WireGuard UDP address: %w", err)
	}
	bridge, err := relay.NewBridge(relay.BridgeConfig{
		RelayURL: cfg.RelayURL, Ticket: cfg.Ticket, SessionID: cfg.SessionID,
		DeviceID: cfg.DeviceID, DestinationDeviceID: cfg.DestinationDeviceID,
		ListenAddress: listenAddress, WireGuardAddress: wireGuardAddress,
	})
	if err != nil {
		return err
	}
	if err := tunnel.EnsureLinuxInterface(ctx, cfg.InterfaceName, cfg.OverlayAddress, cfg.Routes); err != nil {
		return err
	}
	bridgeAddress := bridge.LocalAddr()
	bridgeEndpoint, err := netip.ParseAddrPort(bridgeAddress.String())
	if err != nil {
		return fmt.Errorf("parse relay bridge endpoint: %w", err)
	}
	wireGuardConfig, err := tunnel.BuildWireGuardConfigWithListenPort(cfg.PrivateKey, cfg.ListenPort, []tunnel.PeerConfig{{
		PublicKey: cfg.PeerPublicKey, Endpoint: bridgeEndpoint, AllowedPrefixes: cfg.AllowedPrefixes, PersistentKeepalive: 25 * time.Second,
	}})
	if err != nil {
		return err
	}
	if err := tunnel.ApplyWireGuardConfig(cfg.InterfaceName, wireGuardConfig); err != nil {
		return err
	}
	return bridge.Run(ctx)
}
