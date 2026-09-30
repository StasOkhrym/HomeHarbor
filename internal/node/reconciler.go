package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/sokhrym/go-tunnels/internal/agent/nft"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
	"github.com/sokhrym/go-tunnels/internal/tunnel"
)

// GatewayReconciler applies only snapshots that identify this node as an
// approved gateway. It deliberately ignores client-only snapshots so a client
// cannot accidentally gain forwarding privileges by running the same binary.
type GatewayReconciler struct {
	interfaceName string
	deviceID      string
	policies      *nft.Applier
}

func NewGatewayReconciler(interfaceName, deviceID string) *GatewayReconciler {
	return &GatewayReconciler{interfaceName: interfaceName, deviceID: deviceID, policies: nft.NewApplier(interfaceName, nil)}
}

func (r *GatewayReconciler) Apply(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil || r.policies == nil || r.interfaceName == "" || r.deviceID == "" {
		return errors.New("gateway reconciler is not configured")
	}
	var local snapshot.Device
	var isGateway bool
	for _, gateway := range value.Gateways {
		if gateway.DeviceID == r.deviceID {
			isGateway = true
			break
		}
	}
	if !isGateway {
		return nil
	}
	peers := make(map[string]netip.Prefix, len(value.Devices))
	for _, device := range value.Devices {
		prefix, err := netip.ParsePrefix(device.OverlayAddress)
		if err != nil {
			return fmt.Errorf("device %s has invalid overlay address: %w", device.ID, err)
		}
		peers[device.ID] = prefix
		if device.ID == r.deviceID {
			local = device
		}
	}
	if local.ID == "" {
		return errors.New("gateway device is missing from snapshot")
	}
	overlay, err := netip.ParsePrefix(local.OverlayAddress)
	if err != nil {
		return fmt.Errorf("gateway overlay address: %w", err)
	}
	routes := make([]netip.Prefix, 0)
	for _, route := range value.Routes {
		if route.GatewayID != r.deviceID {
			continue
		}
		prefix, parseErr := netip.ParsePrefix(route.Prefix)
		if parseErr != nil {
			return fmt.Errorf("route %s has invalid prefix: %w", route.ID, parseErr)
		}
		routes = append(routes, prefix)
	}
	if err := tunnel.EnsureLinuxInterface(ctx, r.interfaceName, overlay.String(), routes); err != nil {
		return err
	}
	rules := make([]policy.Rule, 0, len(value.ACL))
	for _, acl := range value.ACL {
		destination, parseErr := netip.ParsePrefix(acl.Destination)
		if parseErr != nil {
			return fmt.Errorf("ACL %s has invalid destination: %w", acl.ID, parseErr)
		}
		protocol := policy.Protocol(acl.Protocol)
		rules = append(rules, policy.Rule{ID: acl.ID, SourceDeviceID: acl.SourceDeviceID, Destination: destination, Protocol: protocol, PortFrom: acl.PortFrom, PortTo: acl.PortTo})
	}
	r.policies.UpdatePeers(peers)
	return r.policies.Apply(ctx, policy.Snapshot{Revision: value.Revision, DefaultAction: policy.ActionDeny, Rules: rules})
}
