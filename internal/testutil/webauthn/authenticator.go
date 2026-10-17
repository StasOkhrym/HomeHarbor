// Package webauthn supplies a software authenticator for protocol-level tests.
// Its keys never leave the test process and it has no browser or OS integration.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type Authenticator struct {
	RPID         string
	Origin       string
	UserVerified bool
	CredentialID []byte
	UserHandle   []byte
	key          *ecdsa.PrivateKey
	counter      uint32
}

func New(t testing.TB, rpID, origin string) *Authenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}

	return &Authenticator{
		RPID:         rpID,
		Origin:       origin,
		UserVerified: true,
		CredentialID: id,
		key:          key,
	}
}

func (a *Authenticator) Registration(t testing.TB, options json.RawMessage) []byte {
	t.Helper()
	var parsed struct {
		PublicKey struct {
			Challenge string
			User      struct{ ID string }
		}
	}

	if err := json.Unmarshal(options, &parsed); err != nil {
		t.Fatal(err)
	}

	var err error

	a.UserHandle, err = base64.RawURLEncoding.DecodeString(parsed.PublicKey.User.ID)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := cbor.Marshal(
		map[int]any{
			1:  2,
			3:  -7,
			-1: 1,
			-2: a.key.X.FillBytes(make([]byte, 32)),
			-3: a.key.Y.FillBytes(make([]byte, 32)),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	authData := a.authData(true)
	authData = append(authData, make([]byte, 16)...)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(a.CredentialID)))
	authData = append(authData, length[:]...)
	authData = append(authData, a.CredentialID...)
	authData = append(authData, publicKey...)
	attestation, err := cbor.Marshal(
		map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData},
	)
	if err != nil {
		t.Fatal(err)
	}

	return a.response(
		t,
		map[string]any{
			"attestationObject": encode(attestation),
			"clientDataJSON": encode(
				a.clientData(t, "webauthn.create", parsed.PublicKey.Challenge),
			),
			"transports": []string{"internal"},
		},
	)
}

func (a *Authenticator) Assertion(t testing.TB, options json.RawMessage) []byte {
	t.Helper()
	var parsed struct{ PublicKey struct{ Challenge string } }

	if err := json.Unmarshal(options, &parsed); err != nil {
		t.Fatal(err)
	}

	clientData := a.clientData(t, "webauthn.get", parsed.PublicKey.Challenge)
	clientHash := sha256.Sum256(clientData)
	authData := a.authData(false)
	signed := append(append([]byte(nil), authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	return a.response(
		t,
		map[string]any{
			"authenticatorData": encode(authData),
			"clientDataJSON":    encode(clientData),
			"signature":         encode(signature),
			"userHandle":        encode(a.UserHandle),
		},
	)
}

func (a *Authenticator) authData(attested bool) []byte {
	rpHash := sha256.Sum256([]byte(a.RPID))
	data := append([]byte(nil), rpHash[:]...)
	flags := byte(1)
	if a.UserVerified {
		flags |= 4
	}

	if attested {
		flags |= 64
	}

	data = append(data, flags)
	a.counter++
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], a.counter)
	return append(data, counter[:]...)
}

func (a *Authenticator) clientData(t testing.TB, kind, challenge string) []byte {
	t.Helper()

	if challenge == "" {
		t.Fatal("authenticator received an empty challenge")
	}

	return marshal(
		t,
		map[string]any{
			"type":        kind,
			"challenge":   challenge,
			"origin":      a.Origin,
			"crossOrigin": false,
		},
	)
}

func (a *Authenticator) response(t testing.TB, response map[string]any) []byte {
	t.Helper()
	return marshal(
		t,
		map[string]any{
			"id":                      encode(a.CredentialID),
			"rawId":                   encode(a.CredentialID),
			"type":                    "public-key",
			"authenticatorAttachment": "platform",
			"clientExtensionResults":  map[string]any{},
			"response":                response,
		},
	)
}
func encode(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
func marshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
