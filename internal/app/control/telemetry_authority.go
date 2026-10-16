package control

import (
	"context"
	"crypto/ed25519"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// Observation authority covers the gateway's signed peer identities. A traffic
// ACL is a separate decision: blocked traffic and credential revocation must
// remain observable until the companion actually removes the signed peer.
func authorizeTelemetryPeer(
	ctx context.Context,
	reader signedSnapshotReader,
	root ed25519.PublicKey,
	networkID string,
	source, destination devices.Device,
) bool {
	if reader == nil || source.ID == destination.ID || source.Role != devices.RoleGateway ||
		source.Status != devices.StatusActive {
		return false
	}

	envelope, err := reader.Latest(ctx)
	if err != nil {
		return false
	}

	value, err := snapshot.Verify(envelope, root, networkID)
	if err != nil {
		return false
	}

	sourceMatches, destinationMatches := false, false
	for _, device := range value.Devices {
		if device.ID == source.ID {
			sourceMatches = device.Role == string(source.Role) &&
				device.WireGuardPublicKey == source.WireGuardPublicKey &&
				device.IdentityPublicKey == source.IdentityPublicKey
		}

		if device.ID == destination.ID {
			destinationMatches = device.Role == string(destination.Role) &&
				device.WireGuardPublicKey == destination.WireGuardPublicKey &&
				device.IdentityPublicKey == destination.IdentityPublicKey
		}
	}

	return sourceMatches && destinationMatches
}
