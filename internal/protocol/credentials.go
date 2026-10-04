package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

const (
	CredentialChallengeTTL   = 60 * time.Second
	credentialRecoveryDomain = "homeharbor/credential-recovery/v1\x00"
)

var ErrInvalidCredentialProof = errors.New("invalid credential proof")

type CredentialLease struct {
	DeviceID   string    `json:"device_id"  cbor:"device_id"`
	Credential string    `json:"credential" cbor:"credential"`
	ExpiresAt  time.Time `json:"expires_at" cbor:"expires_at"`
}
type CredentialChallenge struct {
	Version   uint16 `json:"version"    cbor:"version"`
	NetworkID string `json:"network_id" cbor:"network_id"`
	DeviceID  string `json:"device_id"  cbor:"device_id"`
	Nonce     string `json:"nonce"      cbor:"nonce"`
	ExpiresAt int64  `json:"expires_at" cbor:"expires_at"`
}
type CredentialProof struct {
	Challenge CredentialChallenge `json:"challenge" cbor:"challenge"`
	Signature string              `json:"signature" cbor:"signature"`
}

// EnrolledDevice is a wire projection, independent of persistence records.
type EnrolledDevice struct {
	ID                  string     `json:"id"                    cbor:"id"`
	Name                string     `json:"name"                  cbor:"name"`
	Role                string     `json:"role"                  cbor:"role"`
	Status              string     `json:"status"                cbor:"status"`
	IdentityPublicKey   string     `json:"identity_public_key"   cbor:"identity_public_key"`
	WireGuardPublicKey  string     `json:"wireguard_public_key"  cbor:"wireguard_public_key"`
	CreatedAt           time.Time  `json:"created_at"            cbor:"created_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"  cbor:"revoked_at,omitempty"`
	Credential          string     `json:"credential,omitempty"  cbor:"credential,omitempty"`
	CredentialExpiresAt time.Time  `json:"credential_expires_at" cbor:"credential_expires_at"`
}

func (c CredentialChallenge) SigningBytes() ([]byte, error) {
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(c.Nonce)
	if c.Version != 1 || strings.TrimSpace(c.NetworkID) == "" ||
		strings.TrimSpace(c.DeviceID) == "" ||
		len(c.DeviceID) > 128 ||
		c.ExpiresAt <= 0 ||
		err != nil ||
		len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != c.Nonce {
		return nil, ErrInvalidCredentialProof
	}

	payload, err := companionCanonicalMode.Marshal(c)
	if err != nil {
		return nil, err
	}

	return append([]byte(credentialRecoveryDomain), payload...), nil
}

func SignCredentialProof(c CredentialChallenge, key ed25519.PrivateKey) (CredentialProof, error) {
	b, err := c.SigningBytes()
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return CredentialProof{}, ErrInvalidCredentialProof
	}

	return CredentialProof{
		Challenge: c,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, b)),
	}, nil
}

func VerifyCredentialProof(p CredentialProof, key ed25519.PublicKey) error {
	b, err := p.Challenge.SigningBytes()

	sig, decodeErr := base64.RawURLEncoding.Strict().DecodeString(p.Signature)
	if err != nil || decodeErr != nil || len(key) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(sig) != p.Signature ||
		!ed25519.Verify(key, b, sig) {
		return ErrInvalidCredentialProof
	}

	return nil
}

type EnrollmentRequest struct {
	Token              string `json:"token"                cbor:"token"`
	Name               string `json:"name"                 cbor:"name"`
	IdentityPublicKey  string `json:"identity_public_key"  cbor:"identity_public_key"`
	WireGuardPublicKey string `json:"wireguard_public_key" cbor:"wireguard_public_key"`
}
