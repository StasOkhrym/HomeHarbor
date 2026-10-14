package tunnel

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Identity struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func NewIdentity() (Identity, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Identity{}, fmt.Errorf("generate WireGuard private key: %w", err)
	}

	return Identity{
		PrivateKey: privateKey.String(),
		PublicKey:  privateKey.PublicKey().String(),
	}, nil
}
