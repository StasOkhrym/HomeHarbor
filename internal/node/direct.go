package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	controlprotocol "github.com/sokhrym/go-tunnels/internal/protocol"
)

// HandshakeProber separates endpoint selection from the platform-specific
// observation of a fresh WireGuard handshake. Tests can model packet loss
// without creating a kernel interface; Linux uses WireGuardHandshakeProber.
type HandshakeProber interface {
	HandshakeTime(context.Context, string) (time.Time, error)
	WaitForHandshake(context.Context, string, time.Time) error
}

// CandidateSet combines operator-provided host candidates with the latest
// relay-observed server-reflexive address. The relay observation is only a
// routing hint; CandidatePathManager still requires a fresh WireGuard
// handshake before selecting it as the active path.
type CandidateSet struct {
	mu        sync.RWMutex
	static    []controlprotocol.Candidate
	reflexive netip.AddrPort
	changes   chan struct{}
}

// NewCandidateSet creates a candidate store and copies the initial list so a
// CLI flag slice cannot be mutated concurrently with coordination publishing.
func NewCandidateSet(candidates []controlprotocol.Candidate) *CandidateSet {
	return &CandidateSet{static: append([]controlprotocol.Candidate(nil), candidates...), changes: make(chan struct{}, 1)}
}

// SetObservedEndpoint records a relay-observed endpoint for future candidate
// updates. Invalid endpoints are ignored because they cannot pass protocol
// validation and should not disturb the last usable candidate set.
func (s *CandidateSet) SetObservedEndpoint(endpoint netip.AddrPort) {
	if s == nil || !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() {
		return
	}

	s.mu.Lock()
	if endpoint == s.reflexive {
		s.mu.Unlock()
		return
	}

	s.reflexive = endpoint
	select {
	case s.changes <- struct{}{}:
	default:
	}

	s.mu.Unlock()
}

// Changes returns a coalescing notification channel for candidate updates.
// The latest candidate values remain available through Snapshot, so dropping
// duplicate notifications cannot lose state.
func (s *CandidateSet) Changes() <-chan struct{} {
	if s == nil {
		return nil
	}

	return s.changes
}

// Snapshot returns a validated copy suitable for one coordination update. A
// duplicate observed address is omitted so receivers never see ambiguous
// candidate identities or waste a handshake probe on the same endpoint.
func (s *CandidateSet) Snapshot() []controlprotocol.Candidate {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidates := append([]controlprotocol.Candidate(nil), s.static...)
	if s.reflexive.IsValid() {
		address := s.reflexive.String()
		duplicate := false
		for _, candidate := range candidates {
			if candidate.Address == address {
				duplicate = true
				break
			}
		}
		if !duplicate {
			candidates = append(candidates, controlprotocol.Candidate{Type: controlprotocol.CandidateServerReflexive, Address: address, Priority: 200})
		}
	}
	return candidates
}

// WireGuardHandshakeProber reads the kernel handshake timestamp for one
// interface. A candidate is considered usable only when the timestamp advances
// after that candidate was installed, which prevents a previous relay session
// from falsely validating a new direct endpoint.
type WireGuardHandshakeProber struct {
	InterfaceName string
	PollInterval  time.Duration
}

// NewWireGuardHandshakeProber creates the Linux kernel-backed handshake probe.
// The caller still controls the overall attempt timeout through the context.
func NewWireGuardHandshakeProber(interfaceName string) (*WireGuardHandshakeProber, error) {
	if strings.TrimSpace(interfaceName) == "" {
		return nil, errors.New("WireGuard interface is required for handshake probing")
	}
	return &WireGuardHandshakeProber{InterfaceName: interfaceName, PollInterval: 250 * time.Millisecond}, nil
}

func (p *WireGuardHandshakeProber) HandshakeTime(ctx context.Context, publicKey string) (time.Time, error) {
	if p == nil || strings.TrimSpace(p.InterfaceName) == "" {
		return time.Time{}, errors.New("WireGuard handshake prober is not configured")
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse WireGuard peer key: %w", err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return time.Time{}, fmt.Errorf("open WireGuard control: %w", err)
	}
	defer func() { _ = client.Close() }()
	device, err := client.Device(p.InterfaceName)
	if err != nil {
		return time.Time{}, fmt.Errorf("read WireGuard interface %s: %w", p.InterfaceName, err)
	}
	for _, peer := range device.Peers {
		if peer.PublicKey == key {
			return peer.LastHandshakeTime, nil
		}
	}
	return time.Time{}, fmt.Errorf("WireGuard peer %s is not configured", publicKey)
}

func (p *WireGuardHandshakeProber) WaitForHandshake(ctx context.Context, publicKey string, previous time.Time) error {
	interval := 250 * time.Millisecond
	if p != nil && p.PollInterval > 0 {
		interval = p.PollInterval
	}
	for {
		handshake, err := p.HandshakeTime(ctx, publicKey)
		if err != nil {
			return err
		}
		if !handshake.IsZero() && handshake.After(previous) {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// ParseDirectCandidates parses the operator-provided candidate list used by
// the Linux preview. Automatic STUN discovery can later populate the same
// protocol candidates without changing coordination or endpoint ownership.
func ParseDirectCandidates(value string) ([]controlprotocol.Candidate, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	candidates := make([]controlprotocol.Candidate, 0, len(parts))
	for index, part := range parts {
		address, err := netip.ParseAddrPort(strings.TrimSpace(part))
		if err != nil || !address.IsValid() || address.Port() == 0 || address.Addr().IsUnspecified() {
			return nil, fmt.Errorf("candidate %q is invalid", part)
		}
		candidates = append(candidates, controlprotocol.Candidate{Type: controlprotocol.CandidateHost, Address: address.String(), Priority: uint32(len(parts) - index)})
	}
	return candidates, nil
}

// CandidatePathManager owns only the endpoint/path decision for one peer. The
// signed snapshot still owns the peer key and allowed prefixes through the
// PeerEndpointUpdater boundary.
type CandidatePathManager struct {
	localDeviceID  string
	peerDeviceID   string
	peerPublicKey  string
	updater        PeerEndpointUpdater
	selector       *controlprotocol.PathSelector
	prober         HandshakeProber
	handshakeLimit time.Duration
}

// NewCandidatePathManager creates a direct-path selector for one authenticated
// peer pair. A failed direct probe is a normal network outcome and transitions
// the selector to relay; it is not returned as a coordination-stream error.
func NewCandidatePathManager(localDeviceID, peerDeviceID, peerPublicKey string, updater PeerEndpointUpdater, selector *controlprotocol.PathSelector, prober HandshakeProber) (*CandidatePathManager, error) {
	if strings.TrimSpace(localDeviceID) == "" || strings.TrimSpace(peerDeviceID) == "" || updater == nil || selector == nil || prober == nil {
		return nil, errors.New("local device, peer, endpoint updater, selector, and handshake prober are required")
	}
	if _, err := wgtypes.ParseKey(peerPublicKey); err != nil {
		return nil, fmt.Errorf("invalid peer WireGuard public key: %w", err)
	}
	return &CandidatePathManager{localDeviceID: localDeviceID, peerDeviceID: peerDeviceID, peerPublicKey: peerPublicKey, updater: updater, selector: selector, prober: prober, handshakeLimit: 10 * time.Second}, nil
}

// HandleCandidateUpdate tries direct candidates by descending priority. Every
// candidate is installed temporarily, then must produce a handshake newer than
// the baseline captured before the endpoint change; an old relay handshake can
// therefore never make a dead direct endpoint look healthy.
func (m *CandidatePathManager) HandleCandidateUpdate(ctx context.Context, update controlprotocol.CandidateUpdate) error {
	if m == nil {
		return errors.New("candidate path manager is nil")
	}
	if update.DestinationDeviceID != m.localDeviceID {
		return fmt.Errorf("candidate update targets %s, local device is %s", update.DestinationDeviceID, m.localDeviceID)
	}
	if update.SourceDeviceID != m.peerDeviceID {
		return fmt.Errorf("candidate update source %s is not peer %s", update.SourceDeviceID, m.peerDeviceID)
	}
	if err := update.Validate(); err != nil {
		return err
	}
	candidates := make([]controlprotocol.Candidate, 0, len(update.Candidates))
	for _, candidate := range update.Candidates {
		if candidate.Type != controlprotocol.CandidateRelay {
			candidates = append(candidates, candidate)
		}
	}
	slices.SortStableFunc(candidates, func(left, right controlprotocol.Candidate) int {
		if left.Priority > right.Priority {
			return -1
		}
		if left.Priority < right.Priority {
			return 1
		}
		return strings.Compare(left.Address, right.Address)
	})
	for _, candidate := range candidates {
		endpoint, err := netip.ParseAddrPort(candidate.Address)
		if err != nil {
			continue
		}
		baseline, err := m.prober.HandshakeTime(ctx, m.peerPublicKey)
		if err != nil {
			continue
		}
		if err := m.updater.SetPeerEndpoint(ctx, m.peerPublicKey, endpoint); err != nil {
			continue
		}
		probeContext, cancel := context.WithTimeout(ctx, m.handshakeLimit)
		err = m.prober.WaitForHandshake(probeContext, m.peerPublicKey, baseline)
		cancel()
		if err == nil {
			m.selector.DirectHandshakeSucceeded()
			return nil
		}
		// Remove a failed direct endpoint before asking the relay watcher to
		// install its loopback endpoint. This avoids a stale candidate winning
		// the race between two independent transport goroutines.
		_ = m.updater.ClearPeerEndpoint(ctx, m.peerPublicKey)
	}
	m.selector.DirectFailed()
	return nil
}
