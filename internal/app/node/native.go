package node

import (
	"crypto/ed25519"
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/client/macos"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func validateNativeRuntime(role Role, cfg config.Node, platform string) error {
	if role != Client || platform != "darwin" {
		return errors.New("native system networking is opt-in for the macOS client only")
	}
	if cfg.Identity.ControlURL == "" || cfg.Identity.CAFile == "" || cfg.Identity.Token != "" ||
		cfg.Coordination.URL == "" || cfg.Coordination.RootPublicKeyFile == "" ||
		cfg.Coordination.NetworkID == "" || cfg.Relay.WebSocketURL == "" {
		return errors.New(
			"native client requires signed enrollment, explicit TLS trust, coordination and relay",
		)
	}
	if cfg.WireGuard.InterfaceName != "" || cfg.WireGuard.OverlayAddress != "" ||
		cfg.WireGuard.AllowedPrefixes != "" || cfg.WireGuard.Routes != "" ||
		cfg.DNS.Link != "" || cfg.DNS.EnableForwarding || cfg.Direct.Candidates != "" {
		return errors.New(
			"native interface, routes and DNS must come from signed state; direct discovery is not enabled",
		)
	}

	if _, err := macos.ParseBounds(
		cfg.Native.Overlay,
		cfg.Native.Private,
		cfg.Native.Suffix,
	); err != nil {
		return err
	}

	key, err := wgtypes.ParseKey(cfg.WireGuard.PeerPublicKey)
	if err != nil || key == (wgtypes.Key{}) {
		return errors.New("native relay requires the selected gateway public key")
	}

	bridge, bridgeErr := netip.ParseAddrPort(cfg.Relay.ListenAddress)

	wireGuard, wgErr := netip.ParseAddrPort(cfg.Relay.WireGuardAddress)
	loopback := netip.MustParseAddr("127.0.0.1")
	if cfg.WireGuard.ListenPort < 1024 || cfg.WireGuard.ListenPort > 65535 ||
		bridgeErr != nil || wgErr != nil || bridge.Addr() != loopback || wireGuard.Addr() != loopback ||
		bridge.Port() < 1024 || wireGuard.Port() != uint16(cfg.WireGuard.ListenPort) ||
		bridge.Port() == wireGuard.Port() {
		return errors.New(
			"native relay and WireGuard ports require distinct pinned loopback endpoints",
		)
	}

	return nil
}

func prepareNativeController(
	cfg config.Node,
	state node.State,
	root ed25519.PublicKey,
	helper macos.HelperExecutor,
) (*macos.Controller, error) {
	bounds, err := macos.ParseBounds(cfg.Native.Overlay, cfg.Native.Private, cfg.Native.Suffix)
	if err != nil {
		return nil, err
	}

	return macos.NewController(macos.Authority{
		Root: root, NetworkID: cfg.Coordination.NetworkID, DeviceID: state.DeviceID, Bounds: bounds,
	}, state.WireGuard.PrivateKey, cfg.Runtime.OperationTimeout, helper)
}
