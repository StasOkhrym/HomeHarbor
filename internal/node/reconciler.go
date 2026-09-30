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
	dns           DNSApplier
	forwarding    bool
	ensure        func(context.Context, string, string, []netip.Prefix) error
}

// DNSApplier is the small consumer-side contract needed by the gateway. It
// keeps the policy reconciler testable and prevents it from depending on the
// concrete systemd-resolved implementation.
type DNSApplier interface {
	Apply(context.Context, snapshot.NetworkSnapshot) error
}

// ClientReconciler owns only the local WireGuard link address and routes. It
// never enables forwarding or installs nftables rules: a client must consume
// gateway routes, not become a transit router for the host network.
type ClientReconciler struct {
	interfaceName string
	deviceID      string
	ensure        func(context.Context, string, string, []netip.Prefix) error
}

// NewClientReconciler creates the production client network reconciler.
func NewClientReconciler(interfaceName, deviceID string) *ClientReconciler {
	return NewClientReconcilerWithEnsurer(interfaceName, deviceID, tunnel.EnsureLinuxInterface)
}

// NewClientReconcilerWithEnsurer keeps command execution behind a narrow seam
// so snapshot selection can be tested without CAP_NET_ADMIN or a Linux host.
func NewClientReconcilerWithEnsurer(interfaceName, deviceID string, ensure func(context.Context, string, string, []netip.Prefix) error) *ClientReconciler {
	return &ClientReconciler{interfaceName: interfaceName, deviceID: deviceID, ensure: ensure}
}

// Apply reconciles the client's overlay address and every approved LAN route.
// Route validation happens before the command boundary, so a malformed signed
// snapshot cannot partially change the local interface.
func (r *ClientReconciler) Apply(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil || r.interfaceName == "" || r.deviceID == "" || r.ensure == nil {
		return errors.New("client reconciler is not configured")
	}
	var local *snapshot.Device
	for index := range value.Devices {
		if value.Devices[index].ID == r.deviceID {
			local = &value.Devices[index]
			break
		}
	}
	if local == nil {
		return fmt.Errorf("client device %s is missing from snapshot", r.deviceID)
	}
	if local.Role != "client" {
		return fmt.Errorf("device %s is not a client", r.deviceID)
	}
	if _, err := netip.ParsePrefix(local.OverlayAddress); err != nil {
		return fmt.Errorf("client overlay address: %w", err)
	}
	routes := make([]netip.Prefix, 0, len(value.Routes))
	for _, route := range value.Routes {
		prefix, err := netip.ParsePrefix(route.Prefix)
		if err != nil || !prefix.IsValid() || prefix.Bits() == 0 {
			return fmt.Errorf("route %s has invalid non-default prefix", route.ID)
		}
		routes = append(routes, prefix)
	}
	return r.ensure(ctx, r.interfaceName, local.OverlayAddress, routes)
}

// NewGatewayReconciler composes firewall and optional split-DNS ownership.
// The firewall is applied before DNS so a failed policy transaction never
// leaves a new resolver route active without its matching access controls.
func NewGatewayReconciler(interfaceName, deviceID string, dnsReconcilers ...*DNSReconciler) *GatewayReconciler {
	var dnsReconciler *DNSReconciler
	if len(dnsReconcilers) > 0 {
		dnsReconciler = dnsReconcilers[0]
	}
	return NewGatewayReconcilerWithOptions(interfaceName, deviceID, dnsReconciler, false)
}

// NewGatewayReconcilerWithOptions exposes host-wide forwarding as an explicit
// deployment choice. The default constructor remains fail-safe for developers
// and hosts where another network manager owns sysctl state.
func NewGatewayReconcilerWithOptions(interfaceName, deviceID string, dnsReconciler *DNSReconciler, enableForwarding bool) *GatewayReconciler {
	return NewGatewayReconcilerWithEnsurer(interfaceName, deviceID, dnsReconciler, enableForwarding, tunnel.EnsureLinuxInterface)
}

// NewGatewayReconcilerWithEnsurer exposes the host-interface boundary for
// platform tests. The production constructor above always uses the Linux
// implementation, while tests can verify policy/DNS transaction ordering
// without creating a real tunnel device.
func NewGatewayReconcilerWithEnsurer(interfaceName, deviceID string, dnsReconciler DNSApplier, enableForwarding bool, ensure func(context.Context, string, string, []netip.Prefix) error) *GatewayReconciler {
	return &GatewayReconciler{interfaceName: interfaceName, deviceID: deviceID, policies: nft.NewApplier(interfaceName, nil), dns: dnsReconciler, forwarding: enableForwarding, ensure: ensure}
}

func (r *GatewayReconciler) Apply(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil || r.policies == nil || r.interfaceName == "" || r.deviceID == "" || r.ensure == nil {
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
	if err := r.ensure(ctx, r.interfaceName, overlay.String(), routes); err != nil {
		return err
	}
	if r.forwarding {
		if err := tunnel.EnableLinuxForwarding(ctx); err != nil {
			return err
		}
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
	if r.policies.Revision() != value.Revision {
		if err := r.policies.Apply(ctx, policy.Snapshot{Revision: value.Revision, DefaultAction: policy.ActionDeny, Rules: rules}); err != nil {
			return err
		}
	}
	if r.dns != nil {
		// A DNS command can fail after the firewall has committed. The next
		// retry sees the same signed revision, skips the already-installed
		// policy, and gets another chance to reconcile DNS without weakening
		// nftables' monotonic revision invariant.
		if err := r.dns.Apply(ctx, value); err != nil {
			return fmt.Errorf("apply split DNS snapshot revision %d: %w", value.Revision, err)
		}
	}
	return nil
}
