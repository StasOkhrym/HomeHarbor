package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"unicode/utf8"
)

var ErrInvalidRelayPair = errors.New("invalid relay pair identity")

// RelayPairSessionID names one symmetric rendezvous under a pinned network root.
// It is public metadata, not authorization: admission still requires scoped
// device tickets and the root-signed peer policy at both ends.
func RelayPairSessionID(networkID string, root ed25519.PublicKey, a, b string) (string, error) {
	payload, err := relayPairPayload(networkID, root, a, b)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(append([]byte("homeharbor/relay-pair/v1\x00"), payload...))

	return "pair-" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func relayPairPayload(networkID string, root ed25519.PublicKey, a, b string) ([]byte, error) {
	validDevice := func(id string) bool {
		if len(id) == 0 || len(id) > 128 {
			return false
		}

		for _, value := range []byte(id) {
			if value < 0x21 || value > 0x7e {
				return false
			}
		}

		return true
	}
	if networkID == "" || len(networkID) > 256 || !utf8.ValidString(networkID) ||
		len(root) != ed25519.PublicKeySize || a == b || !validDevice(a) || !validDevice(b) {
		return nil, ErrInvalidRelayPair
	}

	if a > b {
		a, b = b, a
	}

	return canonical.Marshal(struct {
		Version   uint16    `cbor:"version"`
		NetworkID string    `cbor:"network_id"`
		Root      []byte    `cbor:"root_public_key"`
		Devices   [2]string `cbor:"device_ids"`
	}{1, networkID, root, [2]string{a, b}})
}
