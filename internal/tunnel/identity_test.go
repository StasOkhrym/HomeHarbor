package tunnel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewIdentityKeepsPrivateKeyOutOfEnrollmentPayload(t *testing.T) {
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.PrivateKey == "" || identity.PublicKey == "" {
		t.Fatalf("identity=%#v", identity)
	}
	payload := identity.EnrollmentPublicKeys("node-identity-public")
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), identity.PrivateKey) {
		t.Fatal("enrollment payload contains private key")
	}
	if payload.WireGuardPublicKey != identity.PublicKey {
		t.Fatalf("public key=%q", payload.WireGuardPublicKey)
	}
}
