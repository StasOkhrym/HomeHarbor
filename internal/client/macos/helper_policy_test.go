package macos

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestHelperPolicyLoadsOnlyPrivateOwnedProvisioning(t *testing.T) {
	root, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	journal := filepath.Join(dir, "journal.json")
	document := HelperPolicyDocument{
		Version: 1, OwnerUID: 501,
		RootPublicKey: base64.RawURLEncoding.EncodeToString(root),
		NetworkID:     "sandbox-network", DeviceID: "client-1",
		LocalWireGuardPublicKey: private.PublicKey().String(),
		Overlay:                 "10.243.0.0/24", Private: "10.241.50.0/24",
		Suffix:         "sandbox.home.arpa",
		BridgeEndpoint: "127.0.0.1:51822", WireGuardListenPort: 51820,
	}
	content, err := json.Marshal(document)
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
		policy.Authority.Bounds.Private.String() != "10.241.50.0/24" ||
		policy.Tunnel.BridgeEndpoint.String() != "127.0.0.1:51822" ||
		policy.Tunnel.ListenPort != 51820 {
		t.Fatalf("wrong provisioned policy: %+v", policy)
	}
	for _, endpoint := range []string{"0.0.0.0:51822", "192.0.2.1:51822", "127.0.0.1:80"} {
		var invalid HelperPolicyDocument
		if err := json.Unmarshal(content, &invalid); err != nil {
			t.Fatal(err)
		}
		invalid.BridgeEndpoint = endpoint
		bad, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadHelperPolicy(path, journal); err == nil {
			t.Fatalf("unsafe relay bridge endpoint accepted: %s", endpoint)
		}
	}
	for _, mutate := range []func(*HelperPolicyDocument){
		func(value *HelperPolicyDocument) { value.Overlay = "0.0.0.0/1" },
		func(value *HelperPolicyDocument) { value.Private = "203.0.113.0/24" },
		func(value *HelperPolicyDocument) { value.Suffix = "../../etc" },
		func(value *HelperPolicyDocument) { value.LocalWireGuardPublicKey = "invalid" },
	} {
		invalid := document
		mutate(&invalid)
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

func TestHelperPolicyPinsLocalWireGuardIdentity(t *testing.T) {
	root, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"version": 1, "owner_uid": 501,
		"root_public_key": base64.RawURLEncoding.EncodeToString(root),
		"network_id":      "sandbox-network", "device_id": "client-1",
		"overlay": "10.243.0.0/24", "private": "10.241.50.0/24",
		"suffix": "sandbox.home.arpa", "bridge_endpoint": "127.0.0.1:51822",
		"wireguard_listen_port":      51820,
		"local_wireguard_public_key": private.PublicKey().String(),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadHelperPolicy(path, filepath.Join(dir, "journal.json"))
	if err != nil || policy.LocalWireGuardPublicKey != private.PublicKey().String() {
		t.Fatalf("pinned local identity missing: policy=%+v err=%v", policy, err)
	}
}
