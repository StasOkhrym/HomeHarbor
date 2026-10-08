package node

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFlagsOverrideTOMLWithoutLosingOtherFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	if err := os.WriteFile(
		path,
		[]byte(
			"[node]\nname = 'from-file'\nstate_path = 'private/state.json'\n[wireguard]\nlisten_port = 12345\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for _, role := range []Role{Client, Gateway} {
		cfg, err := ParseConfig(role, []string{"-config", path, "-name", "from-flag"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Identity.Name != "from-flag" || cfg.Identity.StatePath != "private/state.json" ||
			cfg.WireGuard.ListenPort != 12345 {
			t.Errorf("configuration precedence lost: %+v", cfg)
		}
	}
}

func TestConfigRejectsUnreadableFileAndPositionalArguments(t *testing.T) {
	for _, args := range [][]string{{"-config", "/nonexistent/homeharbor.toml"}, {"unexpected"}} {
		if _, err := ParseConfig(Client, args, io.Discard); err == nil {
			t.Errorf("invalid configuration accepted: %v", args)
		}
	}
}

func TestExplicitNodeTokenSkipsUnreadableLowerFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	if err := os.WriteFile(
		path,
		[]byte("[node]\nenrollment_token_file = '/definitely/missing/token'\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(
		Client,
		[]string{"-config", path, "-token", "from-flag", "-refresh=false"},
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.Token != "from-flag" || cfg.Identity.Refresh {
		t.Fatalf(
			"explicit token/false lost: token=%q refresh=%v",
			cfg.Identity.Token,
			cfg.Identity.Refresh,
		)
	}
}
