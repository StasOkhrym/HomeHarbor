package node

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestNewStateAndAtomicSave(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	if state.IdentityPrivateKey == "" || state.IdentityPublicKey == "" || state.WireGuard.PrivateKey == "" {
		t.Fatalf("state=%#v", state)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err = state.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.IdentityPublicKey != state.IdentityPublicKey {
		t.Fatalf("loaded=%#v", loaded)
	}
}

func TestLoadOrCreatePreservesExistingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.IdentityPublicKey != first.IdentityPublicKey || second.WireGuard.PublicKey != first.WireGuard.PublicKey {
		t.Fatalf("LoadOrCreate replaced identity: first=%#v second=%#v", first, second)
	}
}

func TestLoadRejectsMismatchedPublicKey(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	state.IdentityPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted mismatched identity public key")
	}
}

func TestLoadRejectsPartialEnrollment(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	state.DeviceID = "device-1"
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted partial enrollment")
	}
}
