package tunnel

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Identity struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}
type EnrollmentPublicKeys struct {
	IdentityPublicKey  string `json:"identity_public_key"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
}

func NewIdentity() (Identity, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Identity{}, fmt.Errorf("generate WireGuard private key: %w", err)
	}
	return Identity{PrivateKey: privateKey.String(), PublicKey: privateKey.PublicKey().String()}, nil
}

func (i Identity) EnrollmentPublicKeys(identityPublicKey string) EnrollmentPublicKeys {
	return EnrollmentPublicKeys{IdentityPublicKey: identityPublicKey, WireGuardPublicKey: i.PublicKey}
}

func (i Identity) Save(path string) error {
	data, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func LoadIdentity(path string) (Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}
	var identity Identity
	if err = json.Unmarshal(data, &identity); err != nil {
		return Identity{}, err
	}
	if _, err = wgtypes.ParseKey(identity.PrivateKey); err != nil {
		return Identity{}, fmt.Errorf("parse WireGuard private key: %w", err)
	}
	return identity, nil
}
