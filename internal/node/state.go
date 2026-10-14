package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

type State struct {
	DeviceID            string          `json:"device_id,omitempty"`
	DeviceRole          string          `json:"device_role,omitempty"`
	CredentialExpiresAt time.Time       `json:"credential_expires_at,omitempty"`
	DeviceCredential    string          `json:"device_credential,omitempty"`
	IdentityPrivateKey  string          `json:"identity_private_key"`
	IdentityPublicKey   string          `json:"identity_public_key"`
	WireGuard           tunnel.Identity `json:"wireguard"`
}

// PublicIdentity is the only node state permitted in setup manifests/output.
type PublicIdentity struct {
	DeviceID           string `json:"device_id"`
	IdentityPublicKey  string `json:"identity_public_key"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
}

func (s State) PublicIdentity() PublicIdentity {
	return PublicIdentity{s.DeviceID, s.IdentityPublicKey, s.WireGuard.PublicKey}
}

func NewState() (State, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return State{}, err
	}

	wireGuard, err := tunnel.NewIdentity()
	if err != nil {
		return State{}, err
	}

	return State{
		IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
		IdentityPublicKey:  base64.RawURLEncoding.EncodeToString(publicKey),
		WireGuard:          wireGuard,
	}, nil
}

func (s State) SaveTo(store *localstate.Store) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return store.Replace(append(data, '\n'))
}

// LoadOrCreateFrom requires a lifetime owner acquired before identity creation.
func LoadOrCreateFrom(store *localstate.Store) (State, error) {
	state, err := LoadFrom(store)
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}

	state, err = NewState()
	if err != nil {
		return State{}, err
	}

	if err = state.SaveTo(store); err != nil {
		return State{}, err
	}

	return state, nil
}

// LoadFrom keeps decoding and key validation in the node domain.
func LoadFrom(store *localstate.Store) (State, error) {
	data, err := store.Read()
	if err != nil {
		return State{}, err
	}

	var state State

	if err = json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}

	if err = state.Validate(); err != nil {
		return State{}, err
	}

	return state, nil
}

// Validate checks the persisted public/private key relationship before a node
// reuses local state. A damaged or hand-edited state file must fail closed;
// silently enrolling a new identity would strand the old device and weaken
// the operator's ability to revoke the intended key.
func (s State) Validate() error {
	if s.IdentityPrivateKey == "" || s.IdentityPublicKey == "" || s.WireGuard.PrivateKey == "" ||
		s.WireGuard.PublicKey == "" {
		return errors.New("node state is incomplete")
	}

	identityPrivate, err := base64.RawURLEncoding.DecodeString(s.IdentityPrivateKey)
	if err != nil || len(identityPrivate) != ed25519.PrivateKeySize {
		return errors.New("node identity private key is invalid")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(identityPrivate[:ed25519.SeedSize]), identityPrivate) {
		return errors.New("node identity private key does not match its seed")
	}

	identityPublic, err := base64.RawURLEncoding.DecodeString(s.IdentityPublicKey)
	if err != nil || len(identityPublic) != ed25519.PublicKeySize ||
		!bytes.Equal(
			ed25519.PrivateKey(identityPrivate).Public().(ed25519.PublicKey),
			identityPublic,
		) {
		return errors.New("node identity public key does not match private key")
	}

	wireGuardPrivate, err := wgtypes.ParseKey(s.WireGuard.PrivateKey)
	if err != nil || wireGuardPrivate.PublicKey().String() != s.WireGuard.PublicKey {
		return errors.New("WireGuard public key does not match private key")
	}
	if (s.DeviceID == "") != (s.DeviceCredential == "") {
		return errors.New("enrolled node state must contain both device ID and credential")
	}

	return nil
}
