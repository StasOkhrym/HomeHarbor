package companion

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

var ErrInvalidSnapshotDiff = errors.New("invalid snapshot diff")

// DeviceAddition is the only network mutation currently allowed to be
// auto-signed by the trusted companion. Keeping the operation narrower than a
// generic snapshot editor prevents an invite approval from changing routes,
// ACLs, services, or another device at the same time.
type DeviceAddition struct {
	ProfileID string
	Device    snapshot.Device
}

// SnapshotSigner signs monotonic snapshots after applying a constrained local
// diff. The control plane can publish the result, but it never receives this
// private key or gets to choose additional fields for the mutation.
type SnapshotSigner struct {
	session   *Session
	networkID string
	keyID     string
}

func NewSnapshotSigner(session *Session, networkID, keyID string) *SnapshotSigner {
	return &SnapshotSigner{session: session, networkID: strings.TrimSpace(networkID), keyID: strings.TrimSpace(keyID)}
}

// SignDeviceAddition verifies the current signed head, adds exactly one client
// to one existing profile, and signs the next contiguous revision. It refuses
// a stale/tampered head and never accepts a caller-supplied revision or hash.
func (s *SnapshotSigner) SignDeviceAddition(previous snapshot.Envelope, addition DeviceAddition) (snapshot.Envelope, error) {
	if s == nil || s.session == nil || s.networkID == "" || s.keyID == "" {
		return snapshot.Envelope{}, ErrInvalidSnapshotDiff
	}
	privateKey, err := s.session.PrivateKey()
	if err != nil {
		return snapshot.Envelope{}, err
	}
	value, err := snapshot.Decode(previous)
	if err != nil {
		return snapshot.Envelope{}, fmt.Errorf("decode current snapshot: %w", err)
	}
	if previous.KeyID != s.keyID {
		return snapshot.Envelope{}, ErrInvalidSnapshotDiff
	}
	currentRevision := uint64(0)
	var currentHash []byte
	if value.Revision > 1 {
		currentRevision = value.Revision - 1
		currentHash = value.PreviousHash
	}
	if err := snapshot.VerifyNext(previous, privateKey.Public().(ed25519.PublicKey), s.networkID, currentRevision, currentHash); err != nil {
		return snapshot.Envelope{}, fmt.Errorf("verify current snapshot: %w", err)
	}
	if err := validateDeviceAddition(value, addition); err != nil {
		return snapshot.Envelope{}, err
	}

	next := cloneSnapshot(value)
	next.Revision = value.Revision + 1
	next.PreviousHash = append([]byte(nil), previous.Hash...)
	next.Devices = append(next.Devices, addition.Device)
	for index := range next.Profiles {
		if next.Profiles[index].ID == addition.ProfileID {
			previousMembers := append([]string(nil), next.Profiles[index].DeviceIDs...)
			next.Profiles[index].DeviceIDs = append(next.Profiles[index].DeviceIDs, addition.Device.ID)
			if err := copyProfileACL(next.ACL, &next.ACL, addition.ProfileID, next.Profiles[index].ACLRuleIDs, previousMembers, addition.Device.ID); err != nil {
				return snapshot.Envelope{}, err
			}
			break
		}
	}
	return snapshot.Sign(next, privateKey, s.keyID)
}

// SignDeviceAdditionFromPool allocates a non-overlapping overlay address from
// the trusted companion's configured pool, then applies the same constrained
// device/profile diff as SignDeviceAddition. The caller cannot smuggle an
// arbitrary address through this path.
func (s *SnapshotSigner) SignDeviceAdditionFromPool(previous snapshot.Envelope, addition DeviceAddition, pool netip.Prefix) (snapshot.Envelope, error) {
	value, err := snapshot.Decode(previous)
	if err != nil {
		return snapshot.Envelope{}, fmt.Errorf("decode current snapshot: %w", err)
	}
	used := make([]string, 0, len(value.Devices))
	for _, device := range value.Devices {
		used = append(used, device.OverlayAddress)
	}
	allocated, err := snapshot.AllocateOverlayAddress(pool, used)
	if err != nil {
		return snapshot.Envelope{}, err
	}
	addition.Device.OverlayAddress = allocated.String()
	return s.SignDeviceAddition(previous, addition)
}

// copyProfileACL applies only ACL templates explicitly attached to the
// profile. It refuses a missing template or a template sourced from a device
// outside the profile, preventing membership changes from inheriting unrelated
// access. Empty ACLRuleIDs remain default-deny.
func copyProfileACL(existing []snapshot.ACLRule, destination *[]snapshot.ACLRule, profileID string, ruleIDs, previousMembers []string, newDeviceID string) error {
	memberSet := make(map[string]struct{}, len(previousMembers))
	for _, memberID := range previousMembers {
		memberSet[memberID] = struct{}{}
	}
	existingIDs := make(map[string]struct{}, len(existing))
	rulesByID := make(map[string]snapshot.ACLRule, len(existing))
	for _, rule := range existing {
		existingIDs[rule.ID] = struct{}{}
		rulesByID[rule.ID] = rule
	}
	for _, ruleID := range ruleIDs {
		rule, ok := rulesByID[ruleID]
		if !ok {
			return ErrInvalidSnapshotDiff
		}
		if _, ok := memberSet[rule.SourceDeviceID]; !ok {
			return ErrInvalidSnapshotDiff
		}
		copied := rule
		copied.ID = profileID + "/" + newDeviceID + "/" + ruleID
		if _, exists := existingIDs[copied.ID]; exists {
			return ErrInvalidSnapshotDiff
		}
		copied.SourceDeviceID = newDeviceID
		*destination = append(*destination, copied)
		existingIDs[copied.ID] = struct{}{}
	}
	return nil
}

func validateDeviceAddition(value snapshot.NetworkSnapshot, addition DeviceAddition) error {
	if strings.TrimSpace(addition.ProfileID) == "" || addition.Device.ID == "" || addition.Device.Role != "client" || addition.Device.IdentityPublicKey == "" || addition.Device.WireGuardPublicKey == "" {
		return ErrInvalidSnapshotDiff
	}
	overlay, err := netip.ParsePrefix(addition.Device.OverlayAddress)
	if err != nil || !overlay.IsValid() || overlay.Bits() == 0 {
		return ErrInvalidSnapshotDiff
	}
	profileFound := false
	for _, profile := range value.Profiles {
		if profile.ID != addition.ProfileID {
			continue
		}
		profileFound = true
		for _, deviceID := range profile.DeviceIDs {
			if deviceID == addition.Device.ID {
				return ErrInvalidSnapshotDiff
			}
		}
	}
	if !profileFound {
		return ErrInvalidSnapshotDiff
	}
	for _, device := range value.Devices {
		if device.ID == addition.Device.ID {
			return ErrInvalidSnapshotDiff
		}
	}
	return nil
}

func cloneSnapshot(value snapshot.NetworkSnapshot) snapshot.NetworkSnapshot {
	copy := value
	copy.PreviousHash = append([]byte(nil), value.PreviousHash...)
	copy.Devices = append([]snapshot.Device(nil), value.Devices...)
	copy.Gateways = append([]snapshot.Gateway(nil), value.Gateways...)
	copy.Routes = append([]snapshot.Route(nil), value.Routes...)
	copy.Services = append([]snapshot.Service(nil), value.Services...)
	copy.Profiles = make([]snapshot.AccessProfile, len(value.Profiles))
	for index, profile := range value.Profiles {
		copy.Profiles[index] = profile
		copy.Profiles[index].DeviceIDs = append([]string(nil), profile.DeviceIDs...)
		copy.Profiles[index].ServiceIDs = append([]string(nil), profile.ServiceIDs...)
		copy.Profiles[index].ACLRuleIDs = append([]string(nil), profile.ACLRuleIDs...)
	}

	copy.ACL = append([]snapshot.ACLRule(nil), value.ACL...)

	return copy
}
