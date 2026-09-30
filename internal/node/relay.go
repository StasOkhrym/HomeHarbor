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

// RelayTicketProvider obtains a fresh short-lived relay ticket. It is called
// before each connection attempt so a reconnect cannot silently reuse an
// expired bearer ticket.
type RelayTicketProvider func(context.Context) (string, error)

// RunRelayBridgeLoop reconnects a relay bridge with bounded exponential
// backoff. The UDP listener is recreated per attempt because Bridge owns and
// closes its socket together with its WebSocket connection.
func RunRelayBridgeLoop(ctx context.Context, cfg RelayBridgeConfig, ticketProvider RelayTicketProvider) error {
	if err := validateRelayBridgeConfig(cfg); err != nil {
		return err
	}
	backoff := time.Second
	for {
		if ticketProvider != nil {
			ticket, err := ticketProvider(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if err := waitBackoff(ctx, backoff); err != nil {
					return nil
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			cfg.Ticket = ticket
		}
		err := RunRelayBridge(ctx, cfg)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return nil
		}
		if err := waitBackoff(ctx, backoff); err != nil {
			return nil
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func waitBackoff(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
	// EndpointUpdater lets a snapshot reconciler retain ownership of the full
	// peer set. When set, this relay only publishes its ephemeral local endpoint
	// and never replaces keys or allowed prefixes itself.
	EndpointUpdater PeerEndpointUpdater
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
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("parse prefix %q: default routes are not allowed", part)
		}

		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

// RunRelayBridge owns the bridge until control cancellation or a transport
// failure. Callers should recreate it after credential/session renewal rather
// than mutating a live bridge's ticket.
func RunRelayBridge(ctx context.Context, cfg RelayBridgeConfig) error {
	if err := validateRelayBridgeConfig(cfg); err != nil {
		return err
	}
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

func validateRelayBridgeConfig(cfg RelayBridgeConfig) error {
	if cfg.RelayURL == "" || cfg.Ticket == "" || cfg.SessionID == "" || cfg.DeviceID == "" || cfg.DestinationDeviceID == "" {
		return errors.New("relay URL, ticket, session, and device identities are required")
	}
	if cfg.ListenAddress == "" || cfg.WireGuardAddress == "" {
		return errors.New("relay bridge UDP addresses are required")
	}
	if _, err := net.ResolveUDPAddr("udp", cfg.ListenAddress); err != nil {
		return errors.New("invalid relay bridge listen address: " + err.Error())
	}
	if _, err := net.ResolveUDPAddr("udp", cfg.WireGuardAddress); err != nil {
		return errors.New("invalid WireGuard UDP address: " + err.Error())
	}
	return nil
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
	if cfg.EndpointUpdater != nil {
		if err := cfg.EndpointUpdater.SetPeerEndpoint(ctx, cfg.PeerPublicKey, bridgeEndpoint); err != nil {
			return fmt.Errorf("publish relay endpoint: %w", err)
		}
		bridgeErr := bridge.Run(ctx)
		clearContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = cfg.EndpointUpdater.ClearPeerEndpoint(clearContext, cfg.PeerPublicKey)
		cancel()
		return bridgeErr
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

// RunKernelRelayLoop repeats the idempotent Linux interface/WireGuard setup
// after a relay failure. Reapplying the same peer configuration is deliberate:
// the bridge owns its UDP socket, so a fresh bridge must be bound before the
// encrypted peer can resume forwarding packets.
func RunKernelRelayLoop(ctx context.Context, cfg KernelRelayConfig, ticketProvider RelayTicketProvider) error {
	if cfg.InterfaceName == "" || cfg.PrivateKey == "" || cfg.PeerPublicKey == "" || cfg.OverlayAddress == "" || cfg.ListenPort == 0 {
		return errors.New("kernel relay interface, keys, overlay address, and listen port are required")
	}
	backoff := time.Second
	for {
		if ticketProvider != nil {
			ticket, err := ticketProvider(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if err := waitBackoff(ctx, backoff); err != nil {
					return nil
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			cfg.Ticket = ticket
		}
		err := RunKernelRelay(ctx, cfg)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return nil
		}
		if err := waitBackoff(ctx, backoff); err != nil {
			return nil
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}
