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
	// RelayTransport selects udp_pair_v2. The versioned /relay/udp/v2 URL also
	// selects it, allowing existing thin entrypoints to consume control URLs.
	RelayTransport  string
	RelayHTTPClient *http.Client
	RelayUDPAddress string
	Ticket          string
	// TicketLifetime is returned by control with a freshly issued ticket. When
	// a provider is configured, v2 renews authentication on the existing local
	// socket. Failed renewal never cancels an established v2 packet plane.
	TicketLifetime      time.Duration
	SessionID           string
	DeviceID            string
	DestinationDeviceID string
	ListenAddress       string
	WireGuardAddress    string
	// STUNServer is retained for entrypoint compatibility. UDP v2 obtains its
	// observed endpoint during authenticated binding on the actual data socket.
	STUNServer string
	// OnObservedEndpoint is called when udp_pair_v2 confirms the address from
	// which this node reached the relay. It is metadata for candidate exchange,
	// not an authorization decision or a proof that direct UDP will succeed.
	OnObservedEndpoint func(netip.AddrPort)
}

// RelayTicketProvider obtains a fresh short-lived relay ticket. It is called
// before each connection attempt so a reconnect cannot silently reuse an
// expired bearer ticket.
type RelayTicketProvider func(context.Context) (string, error)

// RunRelayBridgeLoop retries admission with bounded exponential backoff. V2
// keeps its local WireGuard socket across retries, renewals and control outages.
func RunRelayBridgeLoop(
	ctx context.Context,
	cfg RelayBridgeConfig,
	ticketProvider RelayTicketProvider,
) error {
	if err := validateRelayBridgeConfig(cfg); err != nil {
		return err
	}
	if usesUDPV2(cfg) {
		bridge, err := newUDPV2Bridge(cfg)
		if err != nil {
			return err
		}
		return runUDPV2Owner(ctx, cfg, bridge, ticketProvider, bridge.Run)
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
		attemptLifetime := time.Duration(0)
		if ticketProvider != nil {
			attemptLifetime = cfg.TicketLifetime
		}
		err, renewed := runTicketAttempt(
			ctx,
			attemptLifetime,
			func(attemptContext context.Context) error {
				return RunRelayBridge(attemptContext, cfg)
			},
		)
		if ctx.Err() != nil {
			return nil
		}
		if renewed {
			backoff = time.Second
			continue
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

const ticketRenewalSkew = 15 * time.Second

// runTicketAttempt bounds one transport attempt by the ticket lifetime. The
// renewal cancellation is deliberately indistinguishable from normal
// transport shutdown to the bridge; the boolean lets the outer loop refresh
// credentials instead of treating an intentional renewal as a failure.
func runTicketAttempt(
	ctx context.Context,
	lifetime time.Duration,
	run func(context.Context) error,
) (error, bool) {
	if lifetime <= 0 {
		return run(ctx), false
	}
	refreshAfter := lifetime - ticketRenewalSkew
	if refreshAfter <= 0 {
		refreshAfter = lifetime / 2
	}
	if refreshAfter <= 0 {
		refreshAfter = time.Millisecond
	}
	attemptContext, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := time.NewTimer(refreshAfter)
	defer timer.Stop()
	renewal := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		select {
		case <-timer.C:
			renewal <- struct{}{}
			cancel()
		case <-ctx.Done():
		case <-done:
		}
	}()
	err := run(attemptContext)
	close(done)
	if ctx.Err() != nil {
		return nil, false
	}
	select {
	case <-renewal:
		return err, true
	default:
		return err, false
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

// RunRelayBridge owns the bridge until control cancellation or a transport
// failure. Callers should recreate it after credential/session renewal rather
// than mutating a live bridge's ticket.
func RunRelayBridge(ctx context.Context, cfg RelayBridgeConfig) error {
	if err := validateRelayBridgeConfig(cfg); err != nil {
		return err
	}
	if usesUDPV2(cfg) {
		bridge, err := newUDPV2Bridge(cfg)
		if err != nil {
			return err
		}
		return bridge.Run(ctx)
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
	if cfg.RelayTransport != "" && cfg.RelayTransport != relay.UDPPairV2Protocol {
		return errors.New("unsupported relay transport")
	}
	if cfg.RelayUDPAddress != "" && !usesUDPV2(cfg) {
		return errors.New("legacy UDP ingress disabled; udp_pair_v2 TLS control required")
	}
	if (cfg.RelayURL == "" && cfg.RelayUDPAddress == "") || cfg.Ticket == "" ||
		cfg.SessionID == "" ||
		cfg.DeviceID == "" ||
		cfg.DestinationDeviceID == "" {
		return errors.New(
			"relay URL or UDP address, ticket, session, and device identities are required",
		)
	}
	if usesUDPV2(cfg) && !strings.HasPrefix(cfg.RelayURL, "wss://") {
		return errors.New("UDP v2 requires WSS relay control")
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
	if cfg.InterfaceName == "" || cfg.PrivateKey == "" || cfg.PeerPublicKey == "" ||
		cfg.OverlayAddress == "" ||
		cfg.ListenPort == 0 {
		return errors.New(
			"kernel relay interface, keys, overlay address, and listen port are required",
		)
	}
	if err := validateRelayBridgeConfig(cfg.RelayBridgeConfig); err != nil {
		return err
	}
	if usesUDPV2(cfg.RelayBridgeConfig) {
		bridge, err := newUDPV2Bridge(cfg.RelayBridgeConfig)
		if err != nil {
			return err
		}
		defer func() { _ = bridge.Close() }()
		address := bridge.LocalAddr()
		return runKernelRelayBridge(ctx, cfg, bridge, address.AddrPort())
	}
	listenAddress, err := net.ResolveUDPAddr("udp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("invalid relay bridge listen address: %w", err)
	}
	wireGuardAddress, err := net.ResolveUDPAddr("udp", cfg.WireGuardAddress)
	if err != nil {
		return fmt.Errorf("invalid WireGuard UDP address: %w", err)
	}
	var bridge relayBridgeRunner
	var bridgeEndpoint netip.AddrPort
	{
		kernelBridge, bridgeErr := relay.NewBridge(relay.BridgeConfig{
			RelayURL: cfg.RelayURL, Ticket: cfg.Ticket, SessionID: cfg.SessionID,
			DeviceID: cfg.DeviceID, DestinationDeviceID: cfg.DestinationDeviceID,
			ListenAddress: listenAddress, WireGuardAddress: wireGuardAddress,
		})
		if bridgeErr != nil {
			return bridgeErr
		}
		bridge = kernelBridge
		kernelBridgeAddress := kernelBridge.LocalAddr()
		bridgeEndpoint, err = netip.ParseAddrPort(kernelBridgeAddress.String())
	}
	if err != nil {
		return fmt.Errorf("parse relay bridge endpoint: %w", err)
	}
	return runKernelRelayBridge(ctx, cfg, bridge, bridgeEndpoint)
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

// RunKernelRelayLoop repeats the idempotent Linux interface/WireGuard setup
// after a relay failure. Reapplying the same peer configuration is deliberate:
// the bridge owns its UDP socket, so a fresh bridge must be bound before the
// encrypted peer can resume forwarding packets.
func RunKernelRelayLoop(
	ctx context.Context,
	cfg KernelRelayConfig,
	ticketProvider RelayTicketProvider,
) error {
	if cfg.InterfaceName == "" || cfg.PrivateKey == "" || cfg.PeerPublicKey == "" ||
		cfg.OverlayAddress == "" ||
		cfg.ListenPort == 0 {
		return errors.New(
			"kernel relay interface, keys, overlay address, and listen port are required",
		)
	}
	if err := validateRelayBridgeConfig(cfg.RelayBridgeConfig); err != nil {
		return err
	}
	if usesUDPV2(cfg.RelayBridgeConfig) {
		bridge, err := newUDPV2Bridge(cfg.RelayBridgeConfig)
		if err != nil {
			return err
		}
		address := bridge.LocalAddr()
		return runUDPV2Owner(
			ctx,
			cfg.RelayBridgeConfig,
			bridge,
			ticketProvider,
			func(runCtx context.Context) error {
				return runKernelRelayBridge(runCtx, cfg, bridge, address.AddrPort())
			},
		)
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
		attemptLifetime := time.Duration(0)
		if ticketProvider != nil {
			attemptLifetime = cfg.TicketLifetime
		}
		err, renewed := runTicketAttempt(
			ctx,
			attemptLifetime,
			func(attemptContext context.Context) error {
				return RunKernelRelay(attemptContext, cfg)
			},
		)
		if ctx.Err() != nil {
			return nil
		}
		if renewed {
			backoff = time.Second
			continue
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
