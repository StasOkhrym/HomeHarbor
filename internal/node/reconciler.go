package node

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/agent/nft"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

// GatewayReconciler owns the tunnel firewall, link routes and optional DNS.
// Removing this node's gateway approval installs an empty deny policy and
// revokes owned routes/DNS rather than retaining the previous gateway state.
type GatewayReconciler struct {
	mu                   sync.Mutex
	interfaceName        string
	deviceID             string
	policies             *nft.Applier
	dns                  DNSApplier
	forwarding           bool
	ensure               func(context.Context, string, string, []netip.Prefix) error
	routes               routeOwnership
	prepared             *gatewayPlan
	guarded              bool
	staged               bool
	revision             uint64
	committedFingerprint [32]byte
}

// StagedSnapshotApplier is the gateway's multi-owner boundary. Parent owns
// serialization and the signed/applied revision cursor: Prepare every owner,
// Guard gateways, ApplyPrepared gateways and Apply other owners, then Commit
// gateways ONLY after WireGuard, routes and DNS all succeeded. Any failure
// returns without Commit and leaves the tunnel closed for same-revision retry.
// Apply is a convenience for a gateway without other state owners; composition
// MUST use ApplyPrepared instead or it would release the guard too early.
type StagedSnapshotApplier interface {
	Prepare(context.Context, snapshot.NetworkSnapshot) error
	Guard(context.Context, snapshot.NetworkSnapshot) error
	ApplyPrepared(context.Context, snapshot.NetworkSnapshot) error
	Commit(context.Context, snapshot.NetworkSnapshot) error
}

type gatewayPlan struct {
	fingerprint [32]byte
	value       snapshot.NetworkSnapshot
	policy      *nft.PreparedPolicy
	overlay     string
	routes      []netip.Prefix
	approved    bool
}

// DNSApplier is the small consumer-side contract needed by the gateway. It
// keeps the policy reconciler testable and prevents it from depending on the
// concrete systemd-resolved implementation.
type DNSApplier interface {
	Prepare(context.Context, snapshot.NetworkSnapshot) error
	Apply(context.Context, snapshot.NetworkSnapshot) error
}

// ClientReconciler owns only the local WireGuard link address and routes. It
// never enables forwarding or installs nftables rules: a client must consume
// gateway routes, not become a transit router for the host network.
type ClientReconciler struct {
	mu            sync.Mutex
	interfaceName string
	deviceID      string
	ensure        func(context.Context, string, string, []netip.Prefix) error
	routes        routeOwnership
}

// NewClientReconciler creates the production client network reconciler.
func NewClientReconciler(interfaceName, deviceID string) *ClientReconciler {
	return NewClientReconcilerWithEnsurer(interfaceName, deviceID, tunnel.EnsureLinuxInterface)
}

// NewClientReconcilerWithEnsurer keeps command execution behind a narrow seam
// so snapshot selection can be tested without CAP_NET_ADMIN or a Linux host.
func NewClientReconcilerWithEnsurer(
	interfaceName, deviceID string,
	ensure func(context.Context, string, string, []netip.Prefix) error,
) *ClientReconciler {
	return &ClientReconciler{
		interfaceName: interfaceName,
		deviceID:      deviceID,
		ensure:        ensure,
		routes:        newRouteOwnership(),
	}
}

// Apply reconciles the client's overlay address and every approved LAN route.
// Route validation happens before the command boundary, so a malformed signed
// snapshot cannot partially change the local interface.
func (r *ClientReconciler) Apply(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil {
		return errors.New("client reconciler is not configured")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.Prepare(ctx, value); err != nil {
		return err
	}

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
		// A verified removal retires this owner's routes without reinstalling
		// global routes still used by other clients. The peer owner clears WG.
		return r.routes.reconcile(ctx, r.interfaceName, nil, func() error { return nil })
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

	return r.routes.reconcile(
		ctx,
		r.interfaceName,
		routes,
		func() error { return r.ensure(ctx, r.interfaceName, local.OverlayAddress, routes) },
	)
}

func (r *ClientReconciler) Prepare(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil || r.ensure == nil || r.deviceID == "" {
		return errors.New("client reconciler is not configured")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if _, err := nft.Compile(
		r.interfaceName,
		nil,
		acl.Snapshot{DefaultAction: acl.ActionDeny},
	); err != nil {
		return err
	}

	found := false
	peers := make(map[string]netip.Prefix, len(value.Devices))
	for _, d := range value.Devices {
		if _, exists := peers[d.ID]; exists {
			return errors.New("duplicate client device identity")
		}

		p, err := netip.ParsePrefix(d.OverlayAddress)
		if err != nil {
			return fmt.Errorf("device %s overlay: %w", d.ID, err)
		}

		peers[d.ID] = p
		if d.ID == r.deviceID {
			found = true
			if err != nil || !p.IsValid() || p.Bits() != p.Addr().BitLen() ||
				p.Addr().IsUnspecified() ||
				d.Role != "client" {
				return errors.New("invalid client overlay identity")
			}
		}
	}

	if !found {
		if value.Revision == 0 {
			return fmt.Errorf("client device %s is missing from snapshot", r.deviceID)
		}

		for _, gateway := range value.Gateways {
			if gateway.DeviceID == r.deviceID {
				return errors.New("removed client retains a gateway binding")
			}
		}
	}

	if _, err := nft.Compile(
		r.interfaceName,
		peers,
		acl.Snapshot{DefaultAction: acl.ActionDeny},
	); err != nil {
		return err
	}

	for _, route := range value.Routes {
		p, err := netip.ParsePrefix(route.Prefix)
		if err != nil || !p.IsValid() || p.Bits() == 0 {
			return fmt.Errorf("route %s has invalid non-default prefix", route.ID)
		}
	}

	_, _, err := prepareDNS(value)

	return err
}

// NewGatewayReconciler composes firewall and optional split-DNS ownership.
// The firewall is applied before DNS so a failed policy transaction never
// leaves a new resolver route active without its matching access controls.
func NewGatewayReconciler(
	interfaceName, deviceID string,
	dnsReconcilers ...*DNSReconciler,
) *GatewayReconciler {
	var dnsReconciler *DNSReconciler
	if len(dnsReconcilers) > 0 {
		dnsReconciler = dnsReconcilers[0]
	}
	return NewGatewayReconcilerWithOptions(interfaceName, deviceID, dnsReconciler, false)
}

// NewGatewayReconcilerWithOptions exposes host-wide forwarding as an explicit
// deployment choice. The default constructor remains fail-safe for developers
// and hosts where another network manager owns sysctl state.
func NewGatewayReconcilerWithOptions(
	interfaceName, deviceID string,
	dnsReconciler *DNSReconciler,
	enableForwarding bool,
) *GatewayReconciler {
	var owner DNSApplier
	if dnsReconciler != nil {
		owner = dnsReconciler
	}

	return NewGatewayReconcilerWithEnsurer(
		interfaceName,
		deviceID,
		owner,
		enableForwarding,
		tunnel.EnsureLinuxInterface,
	)
}

// NewGatewayReconcilerWithEnsurer exposes the host-interface boundary for
// platform tests. The production constructor above always uses the Linux
// implementation, while tests can verify policy/DNS transaction ordering
// without creating a real tunnel device.
func NewGatewayReconcilerWithEnsurer(
	interfaceName, deviceID string,
	dnsReconciler DNSApplier,
	enableForwarding bool,
	ensure func(context.Context, string, string, []netip.Prefix) error,
) *GatewayReconciler {
	return &GatewayReconciler{
		interfaceName: interfaceName,
		deviceID:      deviceID,
		policies:      nft.NewApplier(interfaceName, nil),
		dns:           dnsReconciler,
		forwarding:    enableForwarding,
		ensure:        ensure,
		routes:        newRouteOwnership(),
	}
}

func (r *GatewayReconciler) Apply(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil {
		return errors.New("gateway reconciler is not configured")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.prepare(ctx, value); err != nil {
		return err
	}

	if err := r.guard(ctx, value); err != nil {
		return err
	}

	if err := r.applyPrepared(ctx, value); err != nil {
		return err
	}

	return r.commit(ctx, value)
}

func (r *GatewayReconciler) Prepare(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil {
		return errors.New("gateway reconciler is not configured")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.prepare(ctx, value)
}

func (r *GatewayReconciler) prepare(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil || r.policies == nil || r.interfaceName == "" || r.deviceID == "" ||
		r.ensure == nil {
		return errors.New("gateway reconciler is not configured")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if value.Revision == 0 || value.Revision < r.revision {
		return nft.ErrRevisionRollback
	}
	if value.Revision == r.revision && snapshotFingerprint(value) != r.committedFingerprint {
		return errors.New("different gateway state for committed revision")
	}

	var local snapshot.Device
	var isGateway bool
	for _, gateway := range value.Gateways {
		if gateway.DeviceID == r.deviceID {
			isGateway = true
			break
		}
	}

	peers := make(map[string]netip.Prefix, len(value.Devices))
	for _, device := range value.Devices {
		if _, exists := peers[device.ID]; exists || device.ID == "" {
			return fmt.Errorf("duplicate or empty device ID %s", device.ID)
		}

		prefix, err := netip.ParsePrefix(device.OverlayAddress)
		if err != nil {
			return fmt.Errorf("device %s has invalid overlay address: %w", device.ID, err)
		}

		peers[device.ID] = prefix
		if device.ID == r.deviceID {
			local = device
		}
	}

	if local.ID == "" && isGateway {
		return errors.New("gateway device is missing from snapshot")
	}
	if isGateway && local.Role != "gateway" {
		return errors.New("approved gateway has invalid device role")
	}

	routes := make([]netip.Prefix, 0)
	if isGateway {
		for id, prefix := range peers {
			if id != r.deviceID {
				routes = append(routes, prefix)
			}
		}
	}

	seenRoutes := make(map[string]bool)
	for _, route := range value.Routes {
		if route.ID == "" || seenRoutes[route.ID] {
			return errors.New("duplicate or empty route ID")
		}

		seenRoutes[route.ID] = true

		prefix, parseErr := netip.ParsePrefix(route.Prefix)
		if parseErr != nil || !prefix.IsValid() || prefix.Bits() == 0 {
			return fmt.Errorf("route %s has invalid non-default prefix", route.ID)
		}

		// LANs served by this gateway keep their native host routes. Only
		// another approved gateway's LAN belongs on the encrypted interface.
		if isGateway && route.GatewayID != r.deviceID {
			approved := false
			for _, gateway := range value.Gateways {
				if gateway.DeviceID == route.GatewayID {
					approved = true
				}
			}

			if !approved {
				return fmt.Errorf("route %s references unapproved gateway", route.ID)
			}

			routes = append(routes, prefix.Masked())
		}
	}

	if _, _, err := prepareDNS(value); err != nil {
		return err
	}

	if r.dns != nil {
		if err := r.dns.Prepare(ctx, value); err != nil {
			return err
		}
	}

	rules := make([]acl.Rule, 0, len(value.ACL))
	for _, rule := range value.ACL {
		destination, parseErr := netip.ParsePrefix(rule.Destination)
		if parseErr != nil {
			return fmt.Errorf("ACL %s has invalid destination: %w", rule.ID, parseErr)
		}

		protocol := acl.Protocol(rule.Protocol)
		rules = append(
			rules,
			acl.Rule{
				ID:             rule.ID,
				SourceDeviceID: rule.SourceDeviceID,
				Destination:    destination,
				Protocol:       protocol,
				PortFrom:       rule.PortFrom,
				PortTo:         rule.PortTo,
			},
		)
	}

	// Validate even an unapproved local gateway's ACL before any mutation;
	// its final policy is nevertheless empty so revocation cannot retain allows.
	if _, err := nft.Compile(
		r.interfaceName,
		peers,
		acl.Snapshot{Revision: value.Revision, DefaultAction: acl.ActionDeny, Rules: rules},
	); err != nil {
		return err
	}

	if !isGateway {
		rules = nil
	}

	prepared, err := r.policies.Prepare(
		peers,
		acl.Snapshot{Revision: value.Revision, DefaultAction: acl.ActionDeny, Rules: rules},
	)
	if err != nil {
		return err
	}

	r.prepared = &gatewayPlan{
		fingerprint: snapshotFingerprint(value),
		value:       cloneNetworkSnapshot(value),
		policy:      prepared,
		overlay:     local.OverlayAddress,
		routes:      uniquePrefixes(routes),
		approved:    isGateway,
	}
	r.staged = false

	return nil
}

func snapshotFingerprint(value snapshot.NetworkSnapshot) [32]byte {
	encoded, _ := json.Marshal(value) // NetworkSnapshot contains no fallible JSON values.
	return sha256.Sum256(encoded)
}

func (r *GatewayReconciler) matchesPrepared(value snapshot.NetworkSnapshot) error {
	if r.prepared == nil || r.prepared.fingerprint != snapshotFingerprint(value) {
		return errors.New("snapshot does not match prepared gateway state")
	}

	return nil
}

func (r *GatewayReconciler) Guard(ctx context.Context, value snapshot.NetworkSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.guard(ctx, value)
}

func (r *GatewayReconciler) guard(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if err := r.matchesPrepared(value); err != nil {
		return err
	}

	r.guarded, r.staged = false, false

	if err := r.policies.Guard(ctx); err != nil {
		return err
	}

	r.guarded = true

	return nil
}

// Bootstrap installs a tunnel-only deny before any encrypted path is opened.
// Boot callers must fail startup if this fails; no valid snapshot is required.
func (r *GatewayReconciler) Bootstrap(ctx context.Context) error {
	if r == nil || r.policies == nil {
		return errors.New("gateway reconciler is not configured")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.staged = false

	if err := r.policies.Guard(ctx); err != nil {
		return err
	}

	r.guarded = true

	return nil
}

func (r *GatewayReconciler) ApplyPrepared(
	ctx context.Context,
	value snapshot.NetworkSnapshot,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.applyPrepared(ctx, value)
}

func (r *GatewayReconciler) applyPrepared(
	ctx context.Context,
	value snapshot.NetworkSnapshot,
) error {
	if err := r.matchesPrepared(value); err != nil {
		return err
	}

	if !r.guarded {
		return errors.New("gateway apply requires tunnel deny guard")
	}

	r.staged = false
	plan := r.prepared
	if err := r.routes.reconcile(ctx, r.interfaceName, plan.routes, func() error {
		if !plan.approved {
			return nil
		}

		return r.ensure(ctx, r.interfaceName, plan.overlay, plan.routes)
	}); err != nil {
		return err
	}

	if r.forwarding && plan.approved {
		if err := tunnel.EnableLinuxForwarding(ctx); err != nil {
			return err
		}
	}

	if r.dns != nil {
		dnsValue := cloneNetworkSnapshot(plan.value)
		if !plan.approved {
			dnsValue.Routes = nil
		}

		if err := r.dns.Apply(ctx, dnsValue); err != nil {
			return fmt.Errorf("apply split DNS snapshot revision %d: %w", value.Revision, err)
		}
	}

	r.staged = true

	return nil
}

func (r *GatewayReconciler) Commit(ctx context.Context, value snapshot.NetworkSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.commit(ctx, value)
}

func (r *GatewayReconciler) commit(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if err := r.matchesPrepared(value); err != nil {
		return err
	}

	if !r.guarded || !r.staged {
		return errors.New("gateway commit requires successful guarded apply")
	}

	if err := r.policies.Commit(ctx, r.prepared.policy); err != nil {
		return err
	}

	r.revision, r.guarded, r.staged = value.Revision, false, false
	r.committedFingerprint = r.prepared.fingerprint

	return nil
}

func (r *GatewayReconciler) Revision() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.revision
}
