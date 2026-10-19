package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignedRelayTOMLAndExplicitFalseHaveStableSourcePrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")

	if err := os.WriteFile(path, []byte("[relay]\nsigned_peers = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	noEnv := func(string) (string, bool) { return "", false }

	loaded, err := LoadAgent(Sources{File: path, Env: noEnv})

	if err != nil || !loaded.Relay.SignedPeers {
		t.Fatalf("signed TOML mode not loaded: %v", err)
	}

	loaded, err = LoadAgent(
		Sources{File: path, Env: noEnv, Flags: map[string]string{"relay.signed_peers": "false"}},
	)

	if err != nil || loaded.Relay.SignedPeers {
		t.Fatalf("explicit false cannot select legacy mode: %v", err)
	}

	legacy, err := LoadAgent(Sources{Env: noEnv})

	if err != nil || legacy.Relay.SignedPeers {
		t.Fatal("new mode became a default")
	}
}
