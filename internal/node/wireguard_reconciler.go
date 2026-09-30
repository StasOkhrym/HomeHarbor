package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
	"github.com/sokhrym/go-tunnels/internal/tunnel"
)

// PeerEndpointUpdater is the narrow ownership boundary between transport
// discovery/relay and WireGuard reconciliation. Transport code may propose an
// endpoint, but it cannot replace keys or allowed prefixes from a snapshot.
type PeerEndpointUpdater interface {
	SetPeerEndpoint(context.Context, string, netip.AddrPort) error
	ClearPeerEndpoint(context.Context, string) error
}

type wireGuardConfigApplier func(string, wgtypes.Config) error

// SnapshotWireGuardReconciler owns the complete peer set for one interface.
// Snapshot application and endpoint updates share one mutex and one kernel
// config transaction, so a relay reconnect cannot race a policy revision.
type SnapshotWireGuardReconciler struct {
	mu            sync.Mutex
	interfaceName string
	localDeviceID string
	privateKey    string
	listenPort    uint16
	apply         wireGuardConfigApplier
	current       *snapshot.NetworkSnapshot
	endpoints     map[string]netip.AddrPort
}

// NewSnapshotWireGuardReconciler creates an endpoint-aware reconciler. The
// default applier talks to the Linux kernel; tests and dry-run tooling can use
// NewSnapshotWireGuardReconcilerWithApplier with a pure capture function.
func NewSnapshotWireGuardReconciler(interfaceName, localDeviceID, privateKey string, listenPort uint16) (*SnapshotWireGuardReconciler, error) {
	return NewSnapshotWireGuardReconcilerWithApplier(interfaceName, localDeviceID, privateKey, listenPort, tunnel.ApplyWireGuardConfig)
}

func NewSnapshotWireGuardReconcilerWithApplier(interfaceName, localDeviceID, privateKey string, listenPort uint16, applier func(string, wgtypes.Config) error) (*SnapshotWireGuardReconciler, error) {
	if interfaceName == "" || localDeviceID == "" || privateKey == "" || applier == nil {
		return nil, errors.New("WireGuard interface, local device, private key, and applier are required")
	}
	return &SnapshotWireGuardReconciler{interfaceName: interfaceName, localDeviceID: localDeviceID, privateKey: privateKey, listenPort: listenPort, apply: applier, endpoints: make(map[string]netip.AddrPort)}, nil
}

// Apply installs a complete peer set derived from the signed snapshot. A
// failed kernel update leaves both the previous snapshot and endpoint map
// intact, allowing the coordination loop to retry without losing connectivity.
func (r *SnapshotWireGuardReconciler) Apply(ctx context.Context, value snapshot.NetworkSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.validateDesired(value); err != nil {
		return err
	}
	peers, err := r.desiredPeers(value)
	if err != nil {
		return err
	}
	config, err := r.configForPeers(peers)
	if err != nil {
		return err
	}
	if err := r.apply(r.interfaceName, config); err != nil {
		return fmt.Errorf("apply WireGuard snapshot: %w", err)
	}
	copy := cloneNetworkSnapshot(value)
	r.current = &copy
	for publicKey := range r.endpoints {
		if !peerExists(peers, publicKey) {
			delete(r.endpoints, publicKey)
		}
	}
	return nil
}

// Prepare validates identity, topology and the local key without touching
// WireGuard or endpoint ownership. Parent must prepare this owner before the
// gateway guard and any other mutations. Same-revision Apply is intentionally
// repeated after another owner fails; current is WG state, not global success.
func (r *SnapshotWireGuardReconciler) Prepare(ctx context.Context, value snapshot.NetworkSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.validateDesired(value); err != nil {
		return err
	}
	peers, err := r.desiredPeers(value)
	if err != nil {
		return err
	}
	_, err = r.configForPeers(peers)
	return err
}

func (r *SnapshotWireGuardReconciler) desiredPeers(value snapshot.NetworkSnapshot) ([]tunnel.PeerConfig, error) {
	peers, err := BuildWireGuardPeerConfigs(value, r.localDeviceID)
	if !errors.Is(err, ErrLocalDeviceMissing) || value.Revision == 0 {
		return peers, err
	}
	for _, gateway := range value.Gateways {
		if gateway.DeviceID == r.localDeviceID {
			return nil, err
		}
	}
	// A verified revision may revoke this node entirely. Absence means an
	// empty ReplacePeers, not "keep the last working permissions". Do this
	// on restart too: kernel peers can outlive the process's in-memory cursor.
	return nil, nil
}

func (r *SnapshotWireGuardReconciler) validateDesired(value snapshot.NetworkSnapshot) error {
	if r.current != nil {
		if value.Revision < r.current.Revision {
			return errors.New("WireGuard snapshot revision rollback")
		}
		if value.Revision == r.current.Revision && snapshotFingerprint(value) != snapshotFingerprint(*r.current) {
			return errors.New("different WireGuard state for accepted revision")
		}
	}
	addresses := make(map[netip.Addr]bool)
	keys := make(map[wgtypes.Key]bool)
	for _, device := range value.Devices {
		p, err := netip.ParsePrefix(device.OverlayAddress)
		if err != nil || !p.IsValid() || p.Bits() != p.Addr().BitLen() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().Is4In6() {
			return fmt.Errorf("device %s requires a concrete overlay host prefix", device.ID)
		}
		if addresses[p.Addr()] {
			return errors.New("duplicate WireGuard overlay identity")
		}
		addresses[p.Addr()] = true
		key, err := wgtypes.ParseKey(device.WireGuardPublicKey)
		if err != nil || key == (wgtypes.Key{}) {
			return fmt.Errorf("device %s has invalid WireGuard identity", device.ID)
		}
		if keys[key] {
			return errors.New("duplicate WireGuard public key")
		}
		keys[key] = true
		if device.Role != "gateway" && device.Role != "client" {
			return errors.New("invalid WireGuard device role")
		}
	}
	// A LAN route must not give another gateway authority to impersonate an
	// overlay host or overlap a different gateway's cryptokey route ownership.
	for i, route := range value.Routes {
		prefix, err := netip.ParsePrefix(route.Prefix)
		if err != nil || prefix.Bits() == 0 {
			return fmt.Errorf("invalid WireGuard route %s", route.ID)
		}
		for address := range addresses {
			if prefix.Contains(address) {
				return errors.New("LAN route overlaps overlay identity")
			}
		}
		for _, previous := range value.Routes[:i] {
			other, err := netip.ParsePrefix(previous.Prefix)
			if err == nil && previous.GatewayID != route.GatewayID && prefix.Overlaps(other) {
				return errors.New("LAN routes overlap across WireGuard gateways")
			}
		}
	}
	_, _, err := prepareDNS(value)
	return err
}

// SetPeerEndpoint updates only the endpoint of an existing or future peer.
// Before the first snapshot it is cached; after that it is applied together
// with the currently accepted allowed-prefix set.
func (r *SnapshotWireGuardReconciler) SetPeerEndpoint(ctx context.Context, publicKey string, endpoint netip.AddrPort) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if publicKey == "" || !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() {
		return errors.New("valid peer public key and endpoint are required")
	}
	if _, err := wgtypes.ParseKey(publicKey); err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		r.endpoints[publicKey] = endpoint
		return nil
	}
	peers, err := r.desiredPeers(*r.current)
	if err != nil {
		return err
	}
	if !peerExists(peers, publicKey) {
		return fmt.Errorf("peer %s is not present in the accepted snapshot", publicKey)
	}
	previous, hadPrevious := r.endpoints[publicKey]
	r.endpoints[publicKey] = endpoint
	config, configErr := r.configForPeers(peers)
	if configErr == nil {
		configErr = r.apply(r.interfaceName, config)
	}
	if configErr != nil {
		if hadPrevious {
			r.endpoints[publicKey] = previous
		} else {
			delete(r.endpoints, publicKey)
		}
		return fmt.Errorf("apply WireGuard endpoint: %w", configErr)
	}
	return nil
}

// ClearPeerEndpoint removes a relay/direct endpoint while preserving the
// peer's public key and allowed prefixes. A subsequent transport can safely
// install a fresh endpoint without rebuilding policy state.
func (r *SnapshotWireGuardReconciler) ClearPeerEndpoint(ctx context.Context, publicKey string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		delete(r.endpoints, publicKey)
		return nil
	}
	peers, err := r.desiredPeers(*r.current)
	if err != nil {
		return err
	}
	previous, hadPrevious := r.endpoints[publicKey]
	delete(r.endpoints, publicKey)
	config, configErr := r.configForPeers(peers)
	if configErr == nil {
		configErr = r.apply(r.interfaceName, config)
	}
	if configErr != nil && hadPrevious {
		r.endpoints[publicKey] = previous
	}
	if configErr != nil {
		return fmt.Errorf("clear WireGuard endpoint: %w", configErr)
	}
	return nil
}

func (r *SnapshotWireGuardReconciler) configForPeers(peers []tunnel.PeerConfig) (wgtypes.Config, error) {
	for index := range peers {
		if endpoint, ok := r.endpoints[peers[index].PublicKey]; ok {
			peers[index].Endpoint = endpoint
		}
	}
	return tunnel.BuildWireGuardConfigWithListenPort(r.privateKey, r.listenPort, peers)
}

func peerExists(peers []tunnel.PeerConfig, publicKey string) bool {
	for _, peer := range peers {
		if peer.PublicKey == publicKey {
			return true
		}
	}

	return false
}

func cloneNetworkSnapshot(value snapshot.NetworkSnapshot) snapshot.NetworkSnapshot {
	copy := value
	copy.Devices = slices.Clone(value.Devices)
	copy.Gateways = slices.Clone(value.Gateways)
	copy.Routes = slices.Clone(value.Routes)
	copy.ACL = slices.Clone(value.ACL)
	copy.PreviousHash = slices.Clone(value.PreviousHash)
	copy.Services = slices.Clone(value.Services)
	copy.Profiles = slices.Clone(value.Profiles)
	for i := range copy.Profiles {
		copy.Profiles[i].DeviceIDs = slices.Clone(value.Profiles[i].DeviceIDs)
		copy.Profiles[i].ServiceIDs = slices.Clone(value.Profiles[i].ServiceIDs)
		copy.Profiles[i].ACLRuleIDs = slices.Clone(value.Profiles[i].ACLRuleIDs)
	}

	return copy
}
