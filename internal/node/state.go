package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

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
	return State{IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(privateKey), IdentityPublicKey: base64.RawURLEncoding.EncodeToString(publicKey), WireGuard: wireGuard}, nil
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
	defer os.Remove(temporaryPath)
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
func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var state State
	if err = json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	if state.IdentityPrivateKey == "" || state.WireGuard.PrivateKey == "" {
		return State{}, errors.New("node state is incomplete")
	}
	return state, nil
}
