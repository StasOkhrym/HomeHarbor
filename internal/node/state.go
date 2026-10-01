package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sokhrym/go-tunnels/internal/tunnel"
)

type State struct {
	DeviceID           string          `json:"device_id,omitempty"`
	DeviceCredential   string          `json:"device_credential,omitempty"`
	IdentityPrivateKey string          `json:"identity_private_key"`
	IdentityPublicKey  string          `json:"identity_public_key"`
	WireGuard          tunnel.Identity `json:"wireguard"`
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

func (s State) Save(path string) error {
	if path == "" {
		return errors.New("state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(append(data, '\n'))
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

// LoadOrCreate makes node identity persistence explicit at the command boundary.
// A restart must reuse the existing WireGuard and device keys; generating a new
// identity would strand the old peer and could accidentally create a second
// device with the same local configuration.
func LoadOrCreate(path string) (State, error) {
	state, err := Load(path)
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
	if err = state.Save(path); err != nil {
		return State{}, err
	}
	return state, nil
}

func Load(path string) (State, error) {
	file, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return State{}, err
	}
	// The state contains both device credentials and WireGuard private keys.
	// Check the opened file before reading it so a copied or manually relaxed
	// state file cannot silently reintroduce private material into the runtime.
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return State{}, errors.New("node state file must be a private regular file")
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return State{}, err
	}
	var state State
	if err = json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	if err := state.Validate(); err != nil {
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
