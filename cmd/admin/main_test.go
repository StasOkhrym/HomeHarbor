package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestAdminFlagPassphraseFileSkipsUnreadableConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.toml")
	if err := os.WriteFile(
		path,
		[]byte("passphrase_file = '/definitely/missing/passphrase'\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	chosen := filepath.Join(dir, "chosen-passphrase")
	if err := os.WriteFile(chosen, []byte("chosen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := flag.NewFlagSet("admin", flag.ContinueOnError)
	selected := flags.String("passphrase-file", "", "")
	if err := flags.Parse([]string{"-passphrase-file", chosen}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadAdminConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	applyAdminString(flags, "passphrase-file", selected, cfg.PassphraseFile)
	secret, err := configuredPassphrase(*selected)
	if err != nil || secret != "chosen" {
		t.Fatalf("selected passphrase: %q, %v", secret, err)
	}
}
