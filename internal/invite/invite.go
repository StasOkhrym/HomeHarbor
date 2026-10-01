// Package invite defines the end-to-end portion of device onboarding. The
// control plane relays permit/proof bytes, but it never receives the short
// code or the one-time invite private key.
package invite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	Version        uint16 = 1
	permitDomain          = "go-tunnels/invite-permit/v1\x00"
	proofDomain           = "go-tunnels/invite-proof/v1\x00"
	approvalDomain        = "go-tunnels/invite-approval/v1\x00"
)

var (
	ErrInvalidPermit   = errors.New("invalid invite permit")
	ErrInvalidProof    = errors.New("invalid invite proof")
	ErrExpiredInvite   = errors.New("invite expired")
	ErrInvalidApproval = errors.New("invalid invite approval")
)

type Permit struct {
	Version      uint16 `cbor:"version"           json:"version"`
	InviteID     string `cbor:"invite_id"         json:"invite_id"`
	NetworkID    string `cbor:"network_id"        json:"network_id"`
	ProfileID    string `cbor:"profile_id"        json:"profile_id"`
	ExpiresAt    int64  `cbor:"expires_at"        json:"expires_at"`
	InvitePublic []byte `cbor:"invite_public_key" json:"invite_public_key"`
}

type SignedPermit struct {
	Version   uint16 `cbor:"version"   json:"version"`
	KeyID     string `cbor:"key_id"    json:"key_id"`
	Payload   []byte `cbor:"payload"   json:"payload"`
	Signature []byte `cbor:"signature" json:"signature"`
}

type Proof struct {
	Version         uint16 `cbor:"version"           json:"version"`
	InviteID        string `cbor:"invite_id"         json:"invite_id"`
	DeviceID        string `cbor:"device_id"         json:"device_id"`
	DevicePublicKey []byte `cbor:"device_public_key" json:"device_public_key"`
	// WireGuardPublicKey is public-only tunnel identity material. The private
	// key is generated and retained by the enrolling node; carrying only this
	// public half lets control create a peer without ever handling plaintext
	// tunnel secrets.
	WireGuardPublicKey []byte `cbor:"wireguard_public_key" json:"wireguard_public_key"`
	CodeDigest         []byte `cbor:"code_digest"          json:"code_digest"`
	Signature          []byte `cbor:"signature"            json:"signature"`
	DeviceSignature    []byte `cbor:"device_signature"     json:"device_signature"`
}

// Approval is the exact, root-signed diff that a trusted companion allows.
// Control accepts it only when every field equals the pending proof record.
type Approval struct {
	Version            uint16 `cbor:"version"              json:"version"`
	InviteID           string `cbor:"invite_id"            json:"invite_id"`
	ProfileID          string `cbor:"profile_id"           json:"profile_id"`
	DeviceID           string `cbor:"device_id"            json:"device_id"`
	DevicePublicKey    []byte `cbor:"device_public_key"    json:"device_public_key"`
	WireGuardPublicKey []byte `cbor:"wireguard_public_key" json:"wireguard_public_key"`
}

type SignedApproval struct {
	Version   uint16 `cbor:"version"   json:"version"`
	Payload   []byte `cbor:"payload"   json:"payload"`
	Signature []byte `cbor:"signature" json:"signature"`
}

type Invite struct {
	Permit     Permit
	Code       string
	privateKey ed25519.PrivateKey
}

// PrivateKey returns a copy for the companion to place in a URL fragment. A
// fragment is never sent in the HTTP request to the control plane; the mobile
// client consumes it locally and should erase it after producing its proof.
func (i Invite) PrivateKey() (ed25519.PrivateKey, error) {
	if len(i.privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPermit
	}

	return ed25519.PrivateKey(append([]byte(nil), i.privateKey...)), nil
}

// Link encodes only onboarding material in the URL fragment. The short code
// is intentionally absent and must be delivered through another channel.
func (i Invite) Link(baseURL string, permit SignedPermit) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" ||
		(parsed.Scheme != "https" && parsed.Hostname() != "localhost") {
		return "", ErrInvalidPermit
	}

	privateKey, err := i.PrivateKey()
	if err != nil {
		return "", err
	}

	permitBytes, err := canonicalMode.Marshal(permit)
	if err != nil {
		return "", err
	}

	fragment := url.Values{}
	fragment.Set("permit", base64.RawURLEncoding.EncodeToString(permitBytes))
	fragment.Set("invite_key", base64.RawURLEncoding.EncodeToString(privateKey))
	parsed.Fragment = fragment.Encode()

	return parsed.String(), nil
}

var canonicalMode = func() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

func New(
	networkID, profileID string,
	ttl time.Duration,
	now time.Time,
	random io.Reader,
) (Invite, error) {
	if strings.TrimSpace(networkID) == "" || strings.TrimSpace(profileID) == "" || ttl <= 0 ||
		random == nil {
		return Invite{}, errors.New("network, profile, TTL, and random source are required")
	}

	var idBytes [16]byte

	if _, err := io.ReadFull(random, idBytes[:]); err != nil {
		return Invite{}, err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return Invite{}, err
	}

	code, err := rand.Int(random, big.NewInt(100_000_000))
	if err != nil {
		return Invite{}, err
	}

	return Invite{
		Permit: Permit{
			Version:      Version,
			InviteID:     base64.RawURLEncoding.EncodeToString(idBytes[:]),
			NetworkID:    networkID,
			ProfileID:    profileID,
			ExpiresAt:    now.Add(ttl).Unix(),
			InvitePublic: publicKey,
		},
		Code:       fmt.Sprintf("%08d", code.Int64()),
		privateKey: privateKey,
	}, nil
}

func SignPermit(permit Permit, root ed25519.PrivateKey, keyID string) (SignedPermit, error) {
	if len(root) != ed25519.PrivateKeySize || strings.TrimSpace(keyID) == "" ||
		permit.Version != Version ||
		permit.InviteID == "" ||
		len(permit.InvitePublic) != ed25519.PublicKeySize {
		return SignedPermit{}, ErrInvalidPermit
	}

	payload, err := canonicalMode.Marshal(permit)
	if err != nil {
		return SignedPermit{}, err
	}

	return SignedPermit{
		Version:   Version,
		KeyID:     keyID,
		Payload:   payload,
		Signature: ed25519.Sign(root, append([]byte(permitDomain), payload...)),
	}, nil
}

func VerifyPermit(
	signed SignedPermit,
	root ed25519.PublicKey,
	networkID string,
	now time.Time,
) error {
	if signed.Version != Version || len(root) != ed25519.PublicKeySize || signed.KeyID == "" ||
		len(signed.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(root, append([]byte(permitDomain), signed.Payload...), signed.Signature) {
		return ErrInvalidPermit
	}

	var permit Permit

	if err := cbor.Unmarshal(signed.Payload, &permit); err != nil {
		return ErrInvalidPermit
	}

	canonical, err := canonicalMode.Marshal(permit)
	if err != nil || string(canonical) != string(signed.Payload) || permit.Version != Version ||
		permit.NetworkID != networkID ||
		len(permit.InvitePublic) != ed25519.PublicKeySize {
		return ErrInvalidPermit
	}
	if now.Unix() >= permit.ExpiresAt {
		return ErrExpiredInvite
	}

	return nil
}

func PermitProfile(signed SignedPermit) (string, error) {
	var permit Permit

	if err := cbor.Unmarshal(
		signed.Payload,
		&permit,
	); err != nil || permit.Version != Version ||
		permit.ProfileID == "" {
		return "", ErrInvalidPermit
	}

	return permit.ProfileID, nil
}

// PermitNetworkID extracts the network binding after decoding the signed
// permit. Callers should still verify the permit before using the value for a
// state transition; this helper is for selecting the already verified domain.
func PermitNetworkID(signed SignedPermit) (string, error) {
	var permit Permit

	if err := cbor.Unmarshal(
		signed.Payload,
		&permit,
	); err != nil || permit.Version != Version ||
		strings.TrimSpace(permit.NetworkID) == "" {
		return "", ErrInvalidPermit
	}

	return permit.NetworkID, nil
}

func (i Invite) Proof(
	deviceID string,
	devicePrivateKey ed25519.PrivateKey,
	code string,
	wireGuardPublicKey []byte,
) (Proof, error) {
	if len(i.privateKey) != ed25519.PrivateKeySize || deviceID == "" ||
		len(devicePrivateKey) != ed25519.PrivateKeySize ||
		!validWireGuardPublicKey(wireGuardPublicKey) ||
		code != i.Code {
		return Proof{}, ErrInvalidProof
	}

	devicePublicKey := devicePrivateKey.Public().(ed25519.PublicKey)
	digest := codeDigest(code)
	proof := Proof{
		Version:            Version,
		InviteID:           i.Permit.InviteID,
		DeviceID:           deviceID,
		DevicePublicKey:    append([]byte(nil), devicePublicKey...),
		WireGuardPublicKey: append([]byte(nil), wireGuardPublicKey...),
		CodeDigest:         digest,
	}
	payload, err := canonicalMode.Marshal(struct {
		Version            uint16 `cbor:"version"`
		InviteID           string `cbor:"invite_id"`
		DeviceID           string `cbor:"device_id"`
		DevicePublicKey    []byte `cbor:"device_public_key"`
		WireGuardPublicKey []byte `cbor:"wireguard_public_key"`
		CodeDigest         []byte `cbor:"code_digest"`
	}{proof.Version, proof.InviteID, proof.DeviceID, proof.DevicePublicKey, proof.WireGuardPublicKey, proof.CodeDigest})
	if err != nil {
		return Proof{}, err
	}

	proof.Signature = ed25519.Sign(i.privateKey, append([]byte(proofDomain), payload...))
	proof.DeviceSignature = ed25519.Sign(devicePrivateKey, append([]byte(proofDomain), payload...))

	return proof, nil
}

func VerifyProof(signed SignedPermit, proof Proof, profileID string, now time.Time) error {
	var permit Permit

	if err := cbor.Unmarshal(
		signed.Payload,
		&permit,
	); err != nil || proof.Version != Version || proof.InviteID != permit.InviteID || proof.DeviceID == "" || permit.ProfileID != profileID || now.Unix() >= permit.ExpiresAt || len(proof.Signature) != ed25519.SignatureSize || len(proof.DeviceSignature) != ed25519.SignatureSize || len(proof.DevicePublicKey) != ed25519.PublicKeySize || !validWireGuardPublicKey(proof.WireGuardPublicKey) ||
		len(proof.CodeDigest) != sha256.Size {
		return ErrInvalidProof
	}

	payload, err := canonicalMode.Marshal(struct {
		Version            uint16 `cbor:"version"`
		InviteID           string `cbor:"invite_id"`
		DeviceID           string `cbor:"device_id"`
		DevicePublicKey    []byte `cbor:"device_public_key"`
		WireGuardPublicKey []byte `cbor:"wireguard_public_key"`
		CodeDigest         []byte `cbor:"code_digest"`
	}{proof.Version, proof.InviteID, proof.DeviceID, proof.DevicePublicKey, proof.WireGuardPublicKey, proof.CodeDigest})
	if err != nil ||
		!ed25519.Verify(
			permit.InvitePublic,
			append([]byte(proofDomain), payload...),
			proof.Signature,
		) ||
		!ed25519.Verify(
			proof.DevicePublicKey,
			append([]byte(proofDomain), payload...),
			proof.DeviceSignature,
		) {
		return ErrInvalidProof
	}

	return nil
}

// validWireGuardPublicKey rejects the all-zero X25519 public value before it
// can enter a signed approval or a device row. The remaining curve/key
// validation is performed by WireGuard when the key is installed; the invite
// protocol only carries the raw 32-byte public half.
func validWireGuardPublicKey(value []byte) bool {
	return len(value) == 32 && !bytes.Equal(value, make([]byte, 32))
}

// VerifyProofWithCode is intended for the trusted companion. The control
// plane can verify the one-time signature, but only the companion knows the
// separately delivered code and can complete the proof verification.
func VerifyProofWithCode(
	signed SignedPermit,
	proof Proof,
	profileID, code string,
	now time.Time,
) error {
	if err := VerifyProof(signed, proof, profileID, now); err != nil {
		return err
	}

	if !bytes.Equal(proof.CodeDigest, codeDigest(code)) {
		return ErrInvalidProof
	}

	return nil
}

func SignApproval(approval Approval, root ed25519.PrivateKey) (SignedApproval, error) {
	if len(root) != ed25519.PrivateKeySize || approval.Version != Version ||
		approval.InviteID == "" ||
		approval.ProfileID == "" ||
		approval.DeviceID == "" ||
		len(approval.DevicePublicKey) != ed25519.PublicKeySize ||
		len(approval.WireGuardPublicKey) != 32 {
		return SignedApproval{}, ErrInvalidApproval
	}

	payload, err := canonicalMode.Marshal(approval)
	if err != nil {
		return SignedApproval{}, err
	}

	return SignedApproval{
		Version:   Version,
		Payload:   payload,
		Signature: ed25519.Sign(root, append([]byte(approvalDomain), payload...)),
	}, nil
}

func VerifyApproval(signed SignedApproval, root ed25519.PublicKey, expected Approval) error {
	if signed.Version != Version || len(root) != ed25519.PublicKeySize ||
		len(signed.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(root, append([]byte(approvalDomain), signed.Payload...), signed.Signature) {
		return ErrInvalidApproval
	}

	var actual Approval

	if err := cbor.Unmarshal(signed.Payload, &actual); err != nil {
		return ErrInvalidApproval
	}

	canonical, err := canonicalMode.Marshal(actual)
	if err != nil || !bytes.Equal(canonical, signed.Payload) || actual.Version != Version ||
		actual.InviteID != expected.InviteID ||
		actual.ProfileID != expected.ProfileID ||
		actual.DeviceID != expected.DeviceID ||
		!bytes.Equal(actual.DevicePublicKey, expected.DevicePublicKey) ||
		!bytes.Equal(actual.WireGuardPublicKey, expected.WireGuardPublicKey) {
		return ErrInvalidApproval
	}

	return nil
}

func codeDigest(code string) []byte {
	hash := sha256.Sum256(append([]byte("go-tunnels/invite-code/v1\x00"), []byte(code)...))
	return hash[:]
}
