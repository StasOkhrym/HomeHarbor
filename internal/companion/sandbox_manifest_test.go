package companion

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// The checked-in manual fixture must reach the same signer as real enrollment.
// A syntactically valid TOML document can still violate the signed contract.
func TestSandboxManifestCanBeSigned(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := LoadSnapshotManifest(
		filepath.Join("..", "..", "deploy", "sandbox", "initial-snapshot.toml"),
	)
	if err != nil {
		t.Fatal(err)
	}

	manifest.Devices[0].IdentityPublicKey = base64.StdEncoding.EncodeToString(public)

	wireguard, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	manifest.Devices[0].WireGuardPublicKey = wireguard.PublicKey().String()

	envelope, err := manifest.SignInitialSnapshot(private, "sandbox-test-root")
	if err != nil {
		t.Fatalf("manual sandbox manifest cannot be published: %v", err)
	}

	if _, err := snapshot.Verify(envelope, public, manifest.NetworkID); err != nil {
		t.Fatal(err)
	}
}
