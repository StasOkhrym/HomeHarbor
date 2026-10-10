package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	nodepath "github.com/StasOkhrym/homeharbor/internal/node/path"
	controlprotocol "github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/relay"
	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

// RelayBridgeConfig binds a node's local WireGuard UDP socket to an encrypted
// relay path. The bridge itself does not know WireGuard keys or policy; those
// concerns remain owned by the tunnel and gateway layers.
type RelayBridgeConfig struct {
	RelayURL string
	// RelayTransport is the control-issued udp_pair capability. Empty is valid
	// for a directly configured bridge; the URL still must be canonical.
	RelayTransport  string
	RelayHTTPClient *http.Client
	Ticket          string
	// TicketLifetime is returned by control with a freshly issued ticket. When
	// a provider is configured, UDP pair renews authentication on the existing local
	// socket. Failed renewal never cancels an established UDP packet plane.
	TicketLifetime      time.Duration
	SessionID           string
	DeviceID            string
	DestinationDeviceID string
	ListenAddress       string
	WireGuardAddress    string
	// OnObservedEndpoint is called when udp_pair confirms the address from
	// which this node reached the relay. It is metadata for candidate exchange,
	// not an authorization decision or a proof that direct UDP will succeed.
	OnObservedEndpoint func(netip.AddrPort)
}

// RelayTicketProvider obtains a fresh short-lived relay ticket. It is called
// before each connection attempt so a reconnect cannot silently reuse an
// expired bearer ticket.
type RelayTicketProvider func(context.Context) (string, error)

// RunRelayBridgeLoop retains one local WireGuard socket through admissions,
// ticket renewals and control outages.
func RunRelayBridgeLoop(
	ctx context.Context,
	cfg RelayBridgeConfig,
	ticketProvider RelayTicketProvider,
) error {
	if err := validateRelayBridgeConfig(cfg); err != nil {
		return err
	}

	bridge, err := newUDPPairBridge(cfg)
	if err != nil {
		return err
	}

	return runUDPPairOwner(ctx, cfg, bridge, ticketProvider, bridge.Run)
}

const ticketRenewalSkew = 15 * time.Second

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
	// PathSelector lets a direct WireGuard handshake supersede the relay
	// endpoint without stopping the already-prepared relay bridge. A later
	// DirectFailed transition installs the bridge endpoint again.
	PathSelector *nodepath.PathSelector
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

// RunRelayBridge owns the authenticated UDP bridge until cancellation or failure.
func RunRelayBridge(ctx context.Context, cfg RelayBridgeConfig) error {
	if err := validateRelayBridgeConfig(cfg); err != nil {
		return err
	}
	bridge, err := newUDPPairBridge(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = bridge.Close() }()
	return bridge.Run(ctx)
}

func validateRelayBridgeConfig(cfg RelayBridgeConfig) error {
	if cfg.RelayTransport != "" && cfg.RelayTransport != relay.UDPPairProtocol {
		return errors.New("unsupported relay transport")
	}

	if err := controlprotocol.ValidateRelayControlURL(cfg.RelayURL); err != nil {
		return err
	}

	if cfg.RelayURL == "" || cfg.Ticket == "" ||
		cfg.SessionID == "" ||
		cfg.DeviceID == "" ||
		cfg.DestinationDeviceID == "" {
		return errors.New(
			"relay URL, ticket, session, and device identities are required",
		)
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

// RunKernelRelay reconciles Linux WireGuard before opening the UDP bridge.
func RunKernelRelay(ctx context.Context, cfg KernelRelayConfig) error {
	if err := validateKernelRelayConfig(cfg); err != nil {
		return err
	}
	bridge, err := newUDPPairBridge(cfg.RelayBridgeConfig)
	if err != nil {
		return err
	}
	defer func() { _ = bridge.Close() }()
	address := bridge.LocalAddr()
	return runKernelRelayBridge(ctx, cfg, bridge, address.AddrPort())
}

func validateKernelRelayConfig(cfg KernelRelayConfig) error {
	if cfg.InterfaceName == "" || cfg.PrivateKey == "" || cfg.PeerPublicKey == "" ||
		cfg.OverlayAddress == "" ||
		cfg.ListenPort == 0 {
		return errors.New(
			"kernel relay interface, keys, overlay address, and listen port are required",
		)
	}

	return validateRelayBridgeConfig(cfg.RelayBridgeConfig)
}

func runKernelRelayBridge(
	ctx context.Context,
	cfg KernelRelayConfig,
	bridge relayBridgeRunner,
	bridgeEndpoint netip.AddrPort,
) error {
	if err := tunnel.EnsureLinuxInterface(
		ctx,
		cfg.InterfaceName,
		cfg.OverlayAddress,
		cfg.Routes,
	); err != nil {
		return err
	}

	if cfg.EndpointUpdater != nil {
		if cfg.PathSelector != nil {
			return runKernelRelayWithPathSelector(ctx, bridge, cfg, bridgeEndpoint)
		}

		if err := cfg.EndpointUpdater.SetPeerEndpoint(
			ctx,
			cfg.PeerPublicKey,
			bridgeEndpoint,
		); err != nil {
			return fmt.Errorf("publish relay endpoint: %w", err)
		}

		bridgeErr := bridge.Run(ctx)
		clearContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = cfg.EndpointUpdater.ClearPeerEndpoint(clearContext, cfg.PeerPublicKey)
		cancel()
		return bridgeErr
	}

	wireGuardConfig, err := tunnel.BuildWireGuardConfigWithListenPort(
		cfg.PrivateKey,
		cfg.ListenPort,
		[]tunnel.PeerConfig{
			{
				PublicKey:           cfg.PeerPublicKey,
				Endpoint:            bridgeEndpoint,
				AllowedPrefixes:     cfg.AllowedPrefixes,
				PersistentKeepalive: 25 * time.Second,
			},
		},
	)
	if err != nil {
		return err
	}

	if err := tunnel.ApplyWireGuardConfig(cfg.InterfaceName, wireGuardConfig); err != nil {
		return err
	}

	return bridge.Run(ctx)
}

type relayBridgeRunner interface {
	Run(context.Context) error
}

func runKernelRelayWithPathSelector(
	ctx context.Context,
	bridge relayBridgeRunner,
	cfg KernelRelayConfig,
	bridgeEndpoint netip.AddrPort,
) error {
	bridgeContext, cancel := context.WithCancel(ctx)
	bridgeErrors := make(chan error, 1)
	bridgeFinished := false
	go func() { bridgeErrors <- bridge.Run(bridgeContext) }()
	defer func() {
		cancel()
		if !bridgeFinished {
			<-bridgeErrors
		}

		if cfg.PathSelector.Current() != controlprotocol.PathRelay {
			return
		}

		clearContext, clearCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = cfg.EndpointUpdater.ClearPeerEndpoint(clearContext, cfg.PeerPublicKey)
		clearCancel()
	}()

	for {
		if cfg.PathSelector.Current() == controlprotocol.PathRelay {
			if err := cfg.EndpointUpdater.SetPeerEndpoint(
				ctx,
				cfg.PeerPublicKey,
				bridgeEndpoint,
			); err != nil {
				return fmt.Errorf("publish relay endpoint: %w", err)
			}
		}

		changes := cfg.PathSelector.Changes()
		select {
		case err := <-bridgeErrors:
			bridgeFinished = true
			return err
		case <-changes:
			// Re-evaluate the selected path. The direct manager owns direct
			// endpoints; this loop only installs/removes the relay endpoint.
		case <-ctx.Done():
			return nil
		}
	}
}

// RunKernelRelayLoop keeps one local endpoint across authenticated rebinds.
func RunKernelRelayLoop(
	ctx context.Context,
	cfg KernelRelayConfig,
	ticketProvider RelayTicketProvider,
) error {
	if err := validateKernelRelayConfig(cfg); err != nil {
		return err
	}

	bridge, err := newUDPPairBridge(cfg.RelayBridgeConfig)
	if err != nil {
		return err
	}

	address := bridge.LocalAddr()

	return runUDPPairOwner(
		ctx,
		cfg.RelayBridgeConfig,
		bridge,
		ticketProvider,
		func(runCtx context.Context) error {
			return runKernelRelayBridge(runCtx, cfg, bridge, address.AddrPort())
		},
	)
}
