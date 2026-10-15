package tunnel

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerConfig struct {
	PublicKey           string
	Endpoint            netip.AddrPort
	AllowedPrefixes     []netip.Prefix
	PersistentKeepalive time.Duration
}

// BuildWireGuardConfigWithListenPort creates the kernel configuration without
// applying it. Keeping construction pure lets snapshot reconciliation validate
// every key, endpoint, and allowed prefix before changing the live interface.
func BuildWireGuardConfigWithListenPort(
	privateKey string,
	listenPort uint16,
	peers []PeerConfig,
) (wgtypes.Config, error) {
	private, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse private key: %w", err)
	}

	replace := true
	config := wgtypes.Config{PrivateKey: &private, ReplacePeers: true}
	if listenPort != 0 {
		port := int(listenPort)
		config.ListenPort = &port
	}

	for _, peer := range peers {
		public, parseErr := wgtypes.ParseKey(peer.PublicKey)
		if parseErr != nil {
			return wgtypes.Config{}, fmt.Errorf("parse peer public key: %w", parseErr)
		}

		allowed := make([]net.IPNet, 0, len(peer.AllowedPrefixes))
		for _, prefix := range peer.AllowedPrefixes {
			if !prefix.IsValid() || prefix.Bits() == 0 {
				return wgtypes.Config{}, fmt.Errorf(
					"peer %s cannot advertise a default route",
					peer.PublicKey,
				)
			}

			bits := prefix.Bits()
			address := prefix.Addr()
			allowed = append(
				allowed,
				net.IPNet{
					IP:   net.IP(address.AsSlice()),
					Mask: net.CIDRMask(bits, address.BitLen()),
				},
			)
		}

		// Discovery may not have supplied an endpoint yet. wgctrl uses nil
		// to omit it; UDPAddrFromAddrPort(zero) produces a non-nil invalid IP.
		var endpoint *net.UDPAddr
		if peer.Endpoint.IsValid() {
			endpoint = net.UDPAddrFromAddrPort(peer.Endpoint)
		}

		keepalive := peer.PersistentKeepalive
		config.Peers = append(
			config.Peers,
			wgtypes.PeerConfig{
				PublicKey:                   public,
				Remove:                      false,
				UpdateOnly:                  false,
				Endpoint:                    endpoint,
				PersistentKeepaliveInterval: &keepalive,
				ReplaceAllowedIPs:           replace,
				AllowedIPs:                  allowed,
			},
		)
	}

	return config, nil
}

func ApplyWireGuardConfig(interfaceName string, config wgtypes.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control: %w", err)
	}
	defer func() { _ = client.Close() }()

	if err = client.ConfigureDevice(interfaceName, config); err != nil {
		return fmt.Errorf("configure WireGuard interface %s: %w", interfaceName, err)
	}

	return nil
}
