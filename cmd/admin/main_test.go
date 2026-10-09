package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The executable is the command boundary: help must not open its config or key.
func TestAdminHelpAndVersionHaveNoEffects(t *testing.T) {
	commands := [][]string{{"--help"}, {"--version"}}
	for _, name := range []string{
		"init-root", "init-snapshot", "invite", "approve", "publish-snapshot", "revoke-device",
	} {
		commands = append(
			commands,
			[]string{name, "--config", "/definitely/missing/admin.toml", "--help"},
		)
	}

	for _, args := range commands {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			command := exec.Command("go", append([]string{"run", "."}, args...)...)

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("admin %v: %v\n%s", args, err, output)
			}

			if len(output) == 0 {
				t.Fatal("expected help or version output")
			}
		})
	}
}

func TestAdminExplicitPassphraseFileOverridesMissingConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "admin.toml")

	if err := os.WriteFile(
		configPath,
		[]byte("passphrase_file = '/definitely/missing/passphrase'\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	chosen := filepath.Join(dir, "chosen-passphrase")

	if err := os.WriteFile(chosen, []byte("chosen\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := filepath.Join(dir, "root-key.age")

	command := exec.Command(
		"go",
		"run",
		".",
		"init-root",
		"--config",
		configPath,
		"--passphrase-file",
		chosen,
		"--key",
		key,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("init-root: %v\n%s", err, output)
	}

	if strings.TrimSpace(string(output)) == "" {
		t.Fatal("expected root public key")
	}

	if info, err := os.Stat(key); err != nil || info.Size() == 0 {
		t.Fatalf("root key: %v", err)
	}
}
