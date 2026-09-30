package node

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
	"github.com/sokhrym/go-tunnels/internal/tunnel"
)

var (
	ErrLocalDeviceMissing = errors.New("local device is missing from snapshot")
	ErrNoGatewayPeer      = errors.New("snapshot has no usable gateway peer")
)

// BuildWireGuardPeerConfigs translates signed snapshot topology into kernel
// peer inputs. Endpoint ownership is deliberately excluded: coordination or
// relay code may update endpoints independently, while this compiler owns only
// public keys and allowed prefixes. A snapshot update therefore cannot erase a
// live relay endpoint by accident.
func BuildWireGuardPeerConfigs(value snapshot.NetworkSnapshot, localDeviceID string) ([]tunnel.PeerConfig, error) {
	if localDeviceID == "" {
		return nil, ErrLocalDeviceMissing
	}
	devices := make(map[string]snapshot.Device, len(value.Devices))
	for _, device := range value.Devices {
		if device.ID == "" {
			return nil, errors.New("snapshot contains a device without an ID")
		}
		if _, err := wgtypes.ParseKey(device.WireGuardPublicKey); err != nil {
			return nil, fmt.Errorf("device %s has invalid WireGuard public key: %w", device.ID, err)
		}
		if _, exists := devices[device.ID]; exists {
			return nil, fmt.Errorf("duplicate device %s", device.ID)
		}
		devices[device.ID] = device
	}
	local, ok := devices[localDeviceID]
	if !ok {
		return nil, ErrLocalDeviceMissing
	}
	gatewayIDs := make(map[string]struct{}, len(value.Gateways))
	for _, gateway := range value.Gateways {
		device, exists := devices[gateway.DeviceID]
		if !exists || device.Role != "gateway" {
			return nil, fmt.Errorf("gateway %s is not a gateway device", gateway.DeviceID)
		}
		gatewayIDs[gateway.DeviceID] = struct{}{}
	}
	routesByGateway := make(map[string][]netip.Prefix)
	for _, route := range value.Routes {
		if _, ok := gatewayIDs[route.GatewayID]; !ok {
			return nil, fmt.Errorf("route %s references a non-gateway", route.ID)
		}
		prefix, err := netip.ParsePrefix(route.Prefix)
		if err != nil || !prefix.IsValid() || prefix.Bits() == 0 {
			return nil, fmt.Errorf("route %s cannot be a default or invalid route", route.ID)
		}
		routesByGateway[route.GatewayID] = append(routesByGateway[route.GatewayID], prefix.Masked())
	}

	peers := make([]tunnel.PeerConfig, 0, len(devices)-1)
	for _, device := range value.Devices {
		if device.ID == local.ID {
			continue
		}
		_, peerIsGateway := gatewayIDs[device.ID]
		if local.Role == "client" && !peerIsGateway {
			continue
		}
		allowed, err := hostPrefix(device.OverlayAddress)
		if err != nil {
			return nil, fmt.Errorf("device %s overlay: %w", device.ID, err)
		}
		if peerIsGateway {
			allowed = append(allowed, routesByGateway[device.ID]...)
		}
		allowed = uniquePrefixes(allowed)
		peers = append(peers, tunnel.PeerConfig{PublicKey: device.WireGuardPublicKey, AllowedPrefixes: allowed, PersistentKeepalive: 25 * time.Second})
	}
	if local.Role == "client" && len(peers) == 0 {
		return nil, ErrNoGatewayPeer
	}
	slices.SortFunc(peers, func(left, right tunnel.PeerConfig) int { return strings.Compare(left.PublicKey, right.PublicKey) })
	return peers, nil
}

func hostPrefix(raw string) ([]netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.IsValid() || prefix.Bits() == 0 {
		return nil, errors.New("overlay must be a non-default prefix")
	}
	return []netip.Prefix{prefix.Masked()}, nil
}

func uniquePrefixes(values []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(values))
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.SortFunc(out, func(left, right netip.Prefix) int { return strings.Compare(left.String(), right.String()) })
	return out
}
