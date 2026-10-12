package macos

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHelperPolicyLoadsOnlyPrivateOwnedProvisioning(t *testing.T) {
	root, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	journal := filepath.Join(dir, "journal.json")
	content, err := json.Marshal(HelperPolicyDocument{
		Version: 1, OwnerUID: 501,
		RootPublicKey: base64.RawURLEncoding.EncodeToString(root),
		NetworkID:     "sandbox-network", DeviceID: "client-1",
		Overlay: "10.243.0.0/24", Private: "10.241.50.0/24",
		Suffix: "sandbox.home.arpa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadHelperPolicy(path, journal)
	if err != nil {
		t.Fatal(err)
	}
	if policy.OwnerUID != 501 || policy.JournalPath != journal ||
		policy.Authority.NetworkID != "sandbox-network" ||
		policy.Authority.Bounds.Private.String() != "10.241.50.0/24" {
		t.Fatalf("wrong provisioned policy: %+v", policy)
	}
	for _, invalid := range []HelperPolicyDocument{
		{Version: 1, OwnerUID: 501, RootPublicKey: base64.RawURLEncoding.EncodeToString(root), NetworkID: "sandbox-network", DeviceID: "client-1", Overlay: "0.0.0.0/1", Private: "10.241.50.0/24", Suffix: "sandbox.home.arpa"},
		{Version: 1, OwnerUID: 501, RootPublicKey: base64.RawURLEncoding.EncodeToString(root), NetworkID: "sandbox-network", DeviceID: "client-1", Overlay: "10.243.0.0/24", Private: "203.0.113.0/24", Suffix: "sandbox.home.arpa"},
		{Version: 1, OwnerUID: 501, RootPublicKey: base64.RawURLEncoding.EncodeToString(root), NetworkID: "sandbox-network", DeviceID: "client-1", Overlay: "10.243.0.0/24", Private: "10.241.50.0/24", Suffix: "../../etc"},
	} {
		bad, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadHelperPolicy(path, journal); err == nil {
			t.Fatalf("unsafe provisioned policy accepted: %+v", invalid)
		}
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHelperPolicy(path, journal); err == nil {
		t.Fatal("world-readable helper policy accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "other"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHelperPolicy(path, journal); err == nil {
		t.Fatal("symlinked helper policy accepted")
	}
}
