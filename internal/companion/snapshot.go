package companion

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
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

// DeviceRemoval is deliberately narrower than a generic snapshot edit. A
// companion may remove one client identity and the ACL entries sourced from
// it, but it cannot silently change routes, gateways, services, or another
// device while processing an operator revoke request.
type DeviceRemoval struct {
	DeviceID string
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
	return &SnapshotSigner{
		session:   session,
		networkID: strings.TrimSpace(networkID),
		keyID:     strings.TrimSpace(keyID),
	}
}

// SignDeviceAddition verifies the current signed head, adds exactly one client
// to one existing profile, and signs the next contiguous revision. It refuses
// a stale/tampered head and never accepts a caller-supplied revision or hash.
func (s *SnapshotSigner) SignDeviceAddition(
	previous snapshot.Envelope,
	addition DeviceAddition,
) (snapshot.Envelope, error) {
	value, privateKey, err := s.currentHead(previous)
	if err != nil {
		return snapshot.Envelope{}, err
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
			next.Profiles[index].DeviceIDs = append(
				next.Profiles[index].DeviceIDs,
				addition.Device.ID,
			)

			if err := copyProfileACL(
				next.ACL,
				&next.ACL,
				addition.ProfileID,
				next.Profiles[index].ACLRuleIDs,
				previousMembers,
				addition.Device.ID,
			); err != nil {
				return snapshot.Envelope{}, err
			}

			break
		}
	}

	return snapshot.Sign(next, privateKey, s.keyID)
}

// SignDeviceRemoval verifies the current signed head and signs exactly one
// client removal. Existing ACL entries are filtered by source device and
// profile references are updated together, so a gateway can apply the new
// snapshot atomically without accepting a partially revoked policy.
func (s *SnapshotSigner) SignDeviceRemoval(
	previous snapshot.Envelope,
	removal DeviceRemoval,
) (snapshot.Envelope, error) {
	value, privateKey, err := s.currentHead(previous)
	if err != nil {
		return snapshot.Envelope{}, err
	}

	if err := validateDeviceRemoval(value, removal); err != nil {
		return snapshot.Envelope{}, err
	}

	next := cloneSnapshot(value)
	next.Revision = value.Revision + 1
	next.PreviousHash = append([]byte(nil), previous.Hash...)

	devices := next.Devices[:0]
	for _, device := range next.Devices {
		if device.ID != removal.DeviceID {
			devices = append(devices, device)
		}
	}

	next.Devices = devices

	removedACL := make(map[string]struct{})
	acl := next.ACL[:0]
	for _, rule := range next.ACL {
		if rule.SourceDeviceID == removal.DeviceID {
			removedACL[rule.ID] = struct{}{}
			continue
		}

		acl = append(acl, rule)
	}

	next.ACL = acl
	for index := range next.Profiles {
		profile := &next.Profiles[index]
		profile.DeviceIDs = removeString(profile.DeviceIDs, removal.DeviceID)
		profile.ACLRuleIDs = removeStrings(profile.ACLRuleIDs, removedACL)
	}

	return snapshot.Sign(next, privateKey, s.keyID)
}

func (s *SnapshotSigner) currentHead(
	previous snapshot.Envelope,
) (snapshot.NetworkSnapshot, ed25519.PrivateKey, error) {
	if s == nil || s.session == nil || s.networkID == "" || s.keyID == "" ||
		previous.KeyID != s.keyID {
		return snapshot.NetworkSnapshot{}, nil, ErrInvalidSnapshotDiff
	}

	privateKey, err := s.session.PrivateKey()
	if err != nil {
		return snapshot.NetworkSnapshot{}, nil, err
	}

	value, err := snapshot.Decode(previous)
	if err != nil {
		return snapshot.NetworkSnapshot{}, nil, fmt.Errorf("decode current snapshot: %w", err)
	}

	currentRevision := uint64(0)
	var currentHash []byte
	if value.Revision > 1 {
		currentRevision = value.Revision - 1
		currentHash = value.PreviousHash
	}

	if err := snapshot.VerifyNext(
		previous,
		privateKey.Public().(ed25519.PublicKey),
		s.networkID,
		currentRevision,
		currentHash,
	); err != nil {
		return snapshot.NetworkSnapshot{}, nil, fmt.Errorf("verify current snapshot: %w", err)
	}

	return value, privateKey, nil
}

// SignDeviceAdditionFromPool allocates a non-overlapping overlay address from
// the trusted companion's configured pool, then applies the same constrained
// device/profile diff as SignDeviceAddition. The caller cannot smuggle an
// arbitrary address through this path.
func (s *SnapshotSigner) SignDeviceAdditionFromPool(
	previous snapshot.Envelope,
	addition DeviceAddition,
	pool netip.Prefix,
) (snapshot.Envelope, error) {
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
func copyProfileACL(
	existing []snapshot.ACLRule,
	destination *[]snapshot.ACLRule,
	profileID string,
	ruleIDs, previousMembers []string,
	newDeviceID string,
) error {
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
	if strings.TrimSpace(addition.ProfileID) == "" || addition.Device.ID == "" ||
		addition.Device.Role != "client" ||
		addition.Device.IdentityPublicKey == "" ||
		addition.Device.WireGuardPublicKey == "" {
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

func validateDeviceRemoval(value snapshot.NetworkSnapshot, removal DeviceRemoval) error {
	if strings.TrimSpace(removal.DeviceID) == "" {
		return ErrInvalidSnapshotDiff
	}

	var found snapshot.Device
	foundDevice := false
	for _, device := range value.Devices {
		if device.ID != removal.DeviceID {
			continue
		}

		found = device
		foundDevice = true
		break
	}

	if !foundDevice || found.Role != "client" {
		return ErrInvalidSnapshotDiff
	}

	for _, gateway := range value.Gateways {
		if gateway.DeviceID == removal.DeviceID {
			return ErrInvalidSnapshotDiff
		}
	}

	for _, route := range value.Routes {
		if route.GatewayID == removal.DeviceID {
			return ErrInvalidSnapshotDiff
		}
	}

	return nil
}

func removeString(values []string, target string) []string {
	filtered := values[:0]
	for _, value := range values {
		if value != target {
			filtered = append(filtered, value)
		}
	}

	return filtered
}

func removeStrings(values []string, targets map[string]struct{}) []string {
	filtered := values[:0]
	for _, value := range values {
		if _, ok := targets[value]; !ok {
			filtered = append(filtered, value)
		}
	}

	return filtered
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
