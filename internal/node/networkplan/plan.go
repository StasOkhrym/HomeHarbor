// Package networkplan compiles a verified snapshot into a bounded client
// network plan shared by the ordinary controller and native helper.
package networkplan

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

const maxPlanEntries = 64

// Bounds are independently provisioned on the native host. Signed state may
// select a subset but cannot broaden these permissions.
type Bounds struct {
	Overlay netip.Prefix
	Private netip.Prefix
	Suffix  string
}

type Peer struct {
	PublicKey       string         `json:"public_key"`
	AllowedPrefixes []netip.Prefix `json:"allowed_prefixes"`
	KeepaliveSecs   int            `json:"keepalive_seconds"`
}

type Resolver struct {
	Suffix  string     `json:"suffix"`
	Address netip.Addr `json:"address"`
}

type Plan struct {
	NetworkID      string         `json:"network_id"`
	DeviceID       string         `json:"device_id"`
	Revision       uint64         `json:"revision"`
	EnvelopeHash   string         `json:"envelope_hash"`
	Revoked        bool           `json:"revoked"`
	OverlayAddress netip.Prefix   `json:"overlay_address"`
	Peers          []Peer         `json:"peers"`
	Routes         []netip.Prefix `json:"routes"`
	DNS            []Resolver     `json:"dns"`
}

// CompileSigned verifies both the signature and independently pinned network
// before deriving every native argument from the signed value.
func CompileSigned(
	envelope snapshot.Envelope,
	root ed25519.PublicKey,
	networkID, deviceID string,
	bounds Bounds,
) (Plan, error) {
	if networkID == "" || deviceID == "" || !validBounds(bounds) {
		return Plan{}, errors.New("native network trust bounds are invalid")
	}

	value, err := snapshot.Verify(envelope, root, networkID)
	if err != nil {
		return Plan{}, fmt.Errorf("verify native snapshot: %w", err)
	}
	if len(value.Devices) > maxPlanEntries || len(value.Routes) > maxPlanEntries {
		return Plan{}, errors.New("native snapshot exceeds bounded plan size")
	}

	local := netip.Prefix{}
	for _, device := range value.Devices {
		address, parseErr := netip.ParsePrefix(device.OverlayAddress)
		if parseErr != nil || !hostIn(address, bounds.Overlay) {
			return Plan{}, fmt.Errorf("device %s is outside the allowed overlay", device.ID)
		}

		if device.ID == deviceID {
			if device.Role != "client" {
				return Plan{}, errors.New("native local device is not a client")
			}

			local = address
		}
	}

	plan := Plan{
		NetworkID: value.NetworkID, DeviceID: deviceID, Revision: value.Revision,
		EnvelopeHash: hex.EncodeToString(envelope.Hash), OverlayAddress: local,
	}
	if !local.IsValid() {
		// A signed removal must tear down previously owned host access even
		// though there is no longer a local address or peer set to install.
		plan.Revoked = true
		return plan, nil
	}

	compiledPeers, err := BuildWireGuardPeerConfigs(value, deviceID)
	if err != nil {
		return Plan{}, err
	}

	plan.Peers = make([]Peer, 0, len(compiledPeers))
	for _, peer := range compiledPeers {
		plan.Peers = append(plan.Peers, Peer{
			PublicKey: peer.PublicKey, AllowedPrefixes: slices.Clone(peer.AllowedPrefixes),
			KeepaliveSecs: int(peer.PersistentKeepalive.Seconds()),
		})
	}

	for _, route := range value.Routes {
		prefix, parseErr := netip.ParsePrefix(route.Prefix)
		if parseErr != nil || !within(prefix, bounds.Private) {
			return Plan{}, fmt.Errorf("route %s is outside allowed private subnet", route.ID)
		}

		plan.Routes = append(plan.Routes, prefix.Masked())
		if route.DomainSuffix == "" {
			continue
		}

		resolver, parseErr := netip.ParseAddr(route.Resolver)
		if parseErr != nil || route.DomainSuffix != bounds.Suffix || !prefix.Contains(resolver) {
			return Plan{}, fmt.Errorf("route %s has foreign DNS settings", route.ID)
		}

		plan.DNS = append(plan.DNS, Resolver{Suffix: route.DomainSuffix, Address: resolver})
	}

	plan.Routes = UniquePrefixes(plan.Routes)
	slices.SortFunc(plan.DNS, func(a, b Resolver) int {
		if a.Suffix != b.Suffix {
			if a.Suffix < b.Suffix {
				return -1
			}

			return 1
		}

		return a.Address.Compare(b.Address)
	})
	plan.DNS = slices.Compact(plan.DNS)
	if len(plan.DNS) > 1 {
		return Plan{}, errors.New("native plan has multiple resolver owners")
	}

	return plan, nil
}

func validBounds(bounds Bounds) bool {
	return bounds.Overlay.IsValid() && bounds.Private.IsValid() &&
		bounds.Overlay.Bits() > 0 && bounds.Private.Bits() > 0 &&
		bounds.Overlay == bounds.Overlay.Masked() &&
		bounds.Private == bounds.Private.Masked() &&
		!bounds.Overlay.Overlaps(bounds.Private) && bounds.Suffix != ""
}

func within(value, scope netip.Prefix) bool {
	return value.IsValid() && value.Bits() > 0 &&
		value.Addr().BitLen() == scope.Addr().BitLen() &&
		value.Bits() >= scope.Bits() && scope.Contains(value.Masked().Addr())
}

func hostIn(value, scope netip.Prefix) bool {
	return within(value, scope) && value.Bits() == value.Addr().BitLen() &&
		!value.Addr().IsUnspecified() && !value.Addr().IsMulticast()
}
