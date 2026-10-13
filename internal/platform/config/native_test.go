package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeClientConfigurationIsExplicitAndUsesChangedFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.toml")

	if err := os.WriteFile(
		path,
		[]byte(
			"[native]\nenabled = true\noverlay = '10.243.0.0/24'\nprivate = '10.241.50.0/24'\nsuffix = 'sandbox.home.arpa'\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClient(Sources{File: path})
	if err != nil {
		t.Fatalf("native file configuration rejected: %v", err)
	}

	if !cfg.Native.Enabled || cfg.Native.Overlay != "10.243.0.0/24" ||
		cfg.Native.Private != "10.241.50.0/24" ||
		cfg.Native.Suffix != "sandbox.home.arpa" {
		t.Fatal("native trust bounds lost during loading")
	}

	cfg, err = LoadClient(
		Sources{
			File:  path,
			Flags: map[string]string{"native.enabled": "false", "native.suffix": "test.home.arpa"},
		},
	)

	if err != nil || cfg.Native.Enabled || cfg.Native.Suffix != "test.home.arpa" {
		t.Fatalf("explicit native flag precedence failed: %+v, %v", cfg.Native, err)
	}
}
