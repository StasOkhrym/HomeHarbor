// Package snapshot defines the signed state exchanged between the trusted
// administrator, control plane, and nodes. It deliberately has no database or
// transport dependency so a future Swift client can implement the same wire
// contract without copying control-plane internals.
package snapshot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const (
	SchemaVersion   uint16 = 1
	signatureDomain        = "go-tunnels/network-snapshot/v1\x00"
)

var (
	ErrInvalidSignature = errors.New("invalid snapshot signature")
	ErrInvalidHash      = errors.New("invalid snapshot hash")
	ErrInvalidSnapshot  = errors.New("invalid snapshot")
	ErrRevisionRollback = errors.New("snapshot revision rollback")
	ErrRevisionGap      = errors.New("snapshot revision gap")
	ErrPreviousHash     = errors.New("snapshot previous hash mismatch")
)

type Device struct {
	ID                 string `cbor:"id"`
	Role               string `cbor:"role"`
	IdentityPublicKey  string `cbor:"identity_public_key"`
	WireGuardPublicKey string `cbor:"wireguard_public_key"`
	OverlayAddress     string `cbor:"overlay_address"`
}

type Gateway struct {
	DeviceID string `cbor:"device_id"`
	Name     string `cbor:"name"`
}

type Route struct {
	ID           string `cbor:"id"`
	GatewayID    string `cbor:"gateway_id"`
	Prefix       string `cbor:"prefix"`
	DomainSuffix string `cbor:"domain_suffix,omitempty"`
	Resolver     string `cbor:"resolver,omitempty"`
}

type Service struct {
	ID          string `cbor:"id"`
	Name        string `cbor:"name"`
	Kind        string `cbor:"kind"`
	URL         string `cbor:"url"`
	NativeURL   string `cbor:"native_url,omitempty"`
	HealthURL   string `cbor:"health_url,omitempty"`
	Description string `cbor:"description,omitempty"`
}

type AccessProfile struct {
	ID         string   `cbor:"id"`
	Name       string   `cbor:"name"`
	DeviceIDs  []string `cbor:"device_ids"`
	ServiceIDs []string `cbor:"service_ids"`
}

type ACLRule struct {
	ID             string `cbor:"id"`
	SourceDeviceID string `cbor:"source_device_id"`
	Destination    string `cbor:"destination"`
	Protocol       string `cbor:"protocol"`
	PortFrom       uint16 `cbor:"port_from"`
	PortTo         uint16 `cbor:"port_to"`
}

type NetworkSnapshot struct {
	Version      uint16          `cbor:"version"`
	NetworkID    string          `cbor:"network_id"`
	Revision     uint64          `cbor:"revision"`
	PreviousHash []byte          `cbor:"previous_hash,omitempty"`
	Devices      []Device        `cbor:"devices"`
	Gateways     []Gateway       `cbor:"gateways"`
	Routes       []Route         `cbor:"routes"`
	Services     []Service       `cbor:"services"`
	Profiles     []AccessProfile `cbor:"profiles"`
	ACL          []ACLRule       `cbor:"acl"`
}

type Envelope struct {
	Version   uint16 `cbor:"version" json:"version"`
	KeyID     string `cbor:"key_id" json:"key_id"`
	Payload   []byte `cbor:"payload" json:"payload"`
	Hash      []byte `cbor:"hash" json:"hash"`
	Signature []byte `cbor:"signature" json:"signature"`
}

var canonicalMode = func() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

func Sign(value NetworkSnapshot, privateKey ed25519.PrivateKey, keyID string) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize || strings.TrimSpace(keyID) == "" {
		return Envelope{}, errors.New("snapshot signing key and key ID are required")
	}
	value.Version = SchemaVersion
	if err := validateAndNormalize(&value); err != nil {
		return Envelope{}, err
	}
	payload, err := canonicalMode.Marshal(value)
	if err != nil {
		return Envelope{}, fmt.Errorf("encode snapshot: %w", err)
	}
	hash := sha256.Sum256(payload)
	signed := append([]byte(signatureDomain), payload...)
	return Envelope{Version: SchemaVersion, KeyID: keyID, Payload: payload, Hash: hash[:], Signature: ed25519.Sign(privateKey, signed)}, nil
}

func VerifyNext(envelope Envelope, publicKey ed25519.PublicKey, networkID string, currentRevision uint64, currentHash []byte) error {
	if envelope.Version != SchemaVersion || len(publicKey) != ed25519.PublicKeySize || envelope.KeyID == "" || len(envelope.Hash) != sha256.Size || len(envelope.Signature) != ed25519.SignatureSize {
		return ErrInvalidSnapshot
	}
	hash := sha256.Sum256(envelope.Payload)
	if !bytes.Equal(hash[:], envelope.Hash) {
		return ErrInvalidHash
	}
	if !ed25519.Verify(publicKey, append([]byte(signatureDomain), envelope.Payload...), envelope.Signature) {
		return ErrInvalidSignature
	}
	var value NetworkSnapshot
	if err := cbor.Unmarshal(envelope.Payload, &value); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	if err := validateAndNormalize(&value); err != nil {
		return err
	}
	canonical, err := canonicalMode.Marshal(value)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return ErrInvalidSnapshot
	}
	if value.NetworkID != networkID {
		return ErrInvalidSnapshot
	}
	if currentRevision == 0 {
		if value.Revision == 0 || len(value.PreviousHash) != 0 {
			return ErrInvalidSnapshot
		}
		return nil
	}
	if value.Revision <= currentRevision {
		return ErrRevisionRollback
	}
	if value.Revision != currentRevision+1 {
		return ErrRevisionGap
	}
	if !bytes.Equal(value.PreviousHash, currentHash) {
		return ErrPreviousHash
	}
	return nil
}

func Decode(envelope Envelope) (NetworkSnapshot, error) {
	var value NetworkSnapshot

	if err := cbor.Unmarshal(envelope.Payload, &value); err != nil {
		return NetworkSnapshot{}, err
	}

	if err := validateAndNormalize(&value); err != nil {
		return NetworkSnapshot{}, err
	}

	return value, nil
}

func validateAndNormalize(value *NetworkSnapshot) error {
	if value.NetworkID == "" || value.Revision == 0 {
		return ErrInvalidSnapshot
	}
	if value.Version == 0 {
		value.Version = SchemaVersion
	}
	if value.Version != SchemaVersion {
		return ErrInvalidSnapshot
	}
	if err := sortUnique("device", value.Devices, func(item Device) string { return item.ID }); err != nil {
		return err
	}
	if err := sortUnique("gateway", value.Gateways, func(item Gateway) string { return item.DeviceID }); err != nil {
		return err
	}
	if err := sortUnique("route", value.Routes, func(item Route) string { return item.ID }); err != nil {
		return err
	}
	if err := sortUnique("service", value.Services, func(item Service) string { return item.ID }); err != nil {
		return err
	}
	if err := sortUnique("profile", value.Profiles, func(item AccessProfile) string { return item.ID }); err != nil {
		return err
	}
	if err := sortUnique("acl rule", value.ACL, func(item ACLRule) string { return item.ID }); err != nil {
		return err
	}
	for _, service := range value.Services {
		if service.ID == "" || service.Name == "" || (service.Kind != "web" && service.Kind != "native") {
			return fmt.Errorf("%w: service identity or kind", ErrInvalidSnapshot)
		}
		parsed, err := url.Parse(service.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("%w: service %s must use HTTPS", ErrInvalidSnapshot, service.ID)
		}
	}
	for index := range value.Profiles {
		profile := &value.Profiles[index]
		if profile.ID == "" || profile.Name == "" {
			return ErrInvalidSnapshot
		}
		slices.Sort(profile.DeviceIDs)
		slices.Sort(profile.ServiceIDs)
	}
	return nil
}

func sortUnique[T any](kind string, values []T, id func(T) string) error {
	for _, value := range values {
		if id(value) == "" {
			return fmt.Errorf("%w: %s ID is required", ErrInvalidSnapshot, kind)
		}
	}

	slices.SortFunc(values, func(left, right T) int { return strings.Compare(id(left), id(right)) })
	for index := 1; index < len(values); index++ {
		if id(values[index-1]) == id(values[index]) {
			return fmt.Errorf("%w: duplicate %s %q", ErrInvalidSnapshot, kind, id(values[index]))
		}
	}

	return nil
}
