package node

import (
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
