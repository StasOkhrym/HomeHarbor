package node

import (
	"net/netip"

	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

var (
	ErrLocalDeviceMissing = networkplan.ErrLocalDeviceMissing
	ErrNoGatewayPeer      = networkplan.ErrNoGatewayPeer
)

// BuildWireGuardPeerConfigs remains the node-facing compiler boundary while
// the same pure peer compiler is shared with the native macOS network plan.
func BuildWireGuardPeerConfigs(
	value snapshot.NetworkSnapshot,
	localDeviceID string,
) ([]tunnel.PeerConfig, error) {
	return networkplan.BuildWireGuardPeerConfigs(value, localDeviceID)
}

func uniquePrefixes(values []netip.Prefix) []netip.Prefix {
	return networkplan.UniquePrefixes(values)
}
