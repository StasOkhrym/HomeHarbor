package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	ClaimTTL    = 2 * time.Minute
	claimDomain = "homeharbor/activation-claim/v1\x00"
)

var ErrInvalidClaim = errors.New("invalid or consumed activation claim")

// ClaimChallenge uses canonical unpadded base64url only for nonce and signature.
// WireGuard public keys remain standard wgtypes.String() throughout storage.
type ClaimChallenge struct {
	Version   uint16 `json:"version"    cbor:"version"`
	NetworkID string `json:"network_id" cbor:"network_id"`
	InviteID  string `json:"invite_id"  cbor:"invite_id"`
	DeviceID  string `json:"device_id"  cbor:"device_id"`
	Nonce     string `json:"nonce"      cbor:"nonce"`
	ExpiresAt int64  `json:"expires_at" cbor:"expires_at"`
}
type ClaimProof struct {
	Challenge ClaimChallenge `json:"challenge"`
	Signature string         `json:"signature"`
}

var canonical = func() cbor.EncMode {
	m, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}

	return m
}()

// ClaimPayload returns the canonical challenge persisted by the one-use claim repository.
func ClaimPayload(c ClaimChallenge) ([]byte, error) {
	if c.Version != 1 || c.NetworkID == "" || c.InviteID == "" || c.DeviceID == "" ||
		c.ExpiresAt <= 0 {
		return nil, ErrInvalidClaim
	}

	if _, err := strictBase64(c.Nonce, 32); err != nil {
		return nil, err
	}

	return canonical.Marshal(c)
}

func strictBase64(raw string, n int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) != n || base64.RawURLEncoding.EncodeToString(b) != raw {
		return nil, ErrInvalidClaim
	}

	return b, nil
}

func SignClaim(c ClaimChallenge, key ed25519.PrivateKey) (ClaimProof, error) {
	if len(key) != ed25519.PrivateKeySize {
		return ClaimProof{}, ErrInvalidClaim
	}

	p, err := ClaimPayload(c)
	if err != nil {
		return ClaimProof{}, err
	}

	return ClaimProof{
		Challenge: c,
		Signature: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(key, append([]byte(claimDomain), p...)),
		),
	}, nil
}

// VerifyClaim verifies possession; expiry and one-use consumption belong to the caller.
func VerifyClaim(proof ClaimProof, key ed25519.PublicKey) error {
	p, err := ClaimPayload(proof.Challenge)
	if err != nil {
		return err
	}

	sig, err := strictBase64(proof.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(key, append([]byte(claimDomain), p...), sig) {
		return ErrInvalidClaim
	}

	return nil
}
