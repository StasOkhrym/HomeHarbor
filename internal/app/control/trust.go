package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	networksnapshot "github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// authorizeRelayPeer makes relay ticket issuance depend on the same signed
// topology consumed by nodes. A role check alone would let an authenticated
// device ask the relay to pair with every active gateway, even when no route
// or ACL grants that relationship. Verifying the envelope again at this
// boundary also prevents a corrupt or tampered metadata store from becoming a
// source of relay authorization without the trusted companion signature.
type signedSnapshotReader interface {
	Latest(context.Context) (networksnapshot.Envelope, error)
}

func authorizeRelayPeer(
	ctx context.Context,
	snapshots signedSnapshotReader,
	rootPublic ed25519.PublicKey,
	networkID string,
	source, destination devices.Device,
) bool {
	if snapshots == nil {
		return false
	}

	envelope, err := snapshots.Latest(ctx)
	if err != nil {
		return false
	}

	if _, err := networksnapshot.Verify(envelope, rootPublic, networkID); err != nil {
		return false
	}

	value, err := networksnapshot.Decode(envelope)
	if err != nil {
		return false
	}

	var sourceDevice, destinationDevice *networksnapshot.Device
	for index := range value.Devices {
		device := &value.Devices[index]
		switch device.ID {
		case source.ID:
			sourceDevice = device
		case destination.ID:
			destinationDevice = device
		}
	}

	if sourceDevice == nil || destinationDevice == nil ||
		sourceDevice.Role != string(source.Role) ||
		destinationDevice.Role != string(destination.Role) ||
		sourceDevice.Role == destinationDevice.Role {
		return false
	}

	clientID, gatewayID := source.ID, destination.ID
	if source.Role == devices.RoleGateway {
		clientID, gatewayID = destination.ID, source.ID
	}

	if source.Role != devices.RoleClient && source.Role != devices.RoleGateway {
		return false
	}
	if destination.Role != devices.RoleClient && destination.Role != devices.RoleGateway {
		return false
	}

	for _, route := range value.Routes {
		if route.GatewayID != gatewayID {
			continue
		}

		routePrefix, routeErr := netip.ParsePrefix(route.Prefix)
		if routeErr != nil {
			continue
		}

		for _, acl := range value.ACL {
			if acl.SourceDeviceID != clientID {
				continue
			}

			aclPrefix, aclErr := netip.ParsePrefix(acl.Destination)
			if aclErr == nil && prefixesOverlap(routePrefix, aclPrefix) {
				return true
			}
		}
	}

	return false
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func loadRootPublicKey(path string) (ed25519.PublicKey, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	value = []byte(strings.TrimSpace(string(value)))
	if decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(value)); decodeErr == nil {
		value = decoded
	}

	if len(value) != ed25519.PublicKeySize {
		return nil, errors.New(
			"trusted companion root public key must be 32 raw or base64url bytes",
		)
	}

	return ed25519.PublicKey(append([]byte(nil), value...)), nil
}
