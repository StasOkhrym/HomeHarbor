package node

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
)

func TestNewStateAndAtomicSave(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	if state.IdentityPrivateKey == "" || state.IdentityPublicKey == "" ||
		state.WireGuard.PrivateKey == "" {
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
	if second.IdentityPublicKey != first.IdentityPublicKey ||
		second.WireGuard.PublicKey != first.WireGuard.PublicKey {
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

func TestLoadRejectsWorldReadableState(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted a state file readable by other users")
	}
}

func TestInvalidKeysFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte(`{"identity_private_key":"invalid"}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("corrupt state generated a replacement identity")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(original) {
		t.Fatalf("corrupt bytes changed: %q, %v", after, err)
	}
}

func TestValidateRejectsInconsistentEd25519Seed(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	private, err := base64.RawURLEncoding.DecodeString(state.IdentityPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	private[0] ^= 0xff
	state.IdentityPrivateKey = base64.RawURLEncoding.EncodeToString(private)
	if err := state.Validate(); err == nil {
		t.Fatal("private seed inconsistent with public key accepted")
	}
}

func TestStateWrappersPreserveErrorsAndReleaseOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	state.CredentialExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	var marshalError *json.MarshalerError
	if err := state.Save(path); !errors.As(err, &marshalError) {
		t.Fatalf("save lost JSON issuance error: %v", err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, load := range []func(string) (State, error){Load, LoadOrCreate} {
		var syntaxError *json.SyntaxError
		if _, err := load(path); !errors.As(err, &syntaxError) {
			t.Fatalf("load lost original JSON error: %v", err)
		}
		owner, err := localstate.Open(path)
		if err != nil {
			t.Fatalf("failed operation leaked lifetime lock: %v", err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
