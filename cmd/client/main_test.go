package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientRejectsUnsignedKernelModeBeforeCreatingIdentity(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "client")

	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build client: %v: %s", err, output)
	}

	state := filepath.Join(t.TempDir(), "client.json")

	output, err := exec.Command(binary, "--wg-interface", "wg0", "--state", state).CombinedOutput()

	if err == nil || !strings.Contains(string(output), "signed coordination") {
		t.Errorf("unsigned kernel client accepted: %v: %s", err, output)
	}

	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("invalid runtime created identity: %v", err)
	}
}

func TestClientVersionDoesNotReadConfig(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "client")

	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build client: %v: %s", err, output)
	}

	output, err := exec.Command(binary, "--version", "--config", "/definitely/missing/node.toml").
		CombinedOutput()

	if err != nil || !strings.Contains(string(output), "client version") {
		t.Fatalf("version used configuration: %v: %s", err, output)
	}
}

func TestClientSyntaxKeepsLegacyExitCode(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "client")

	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build client: %v: %s", err, output)
	}

	for _, args := range [][]string{{"--unknown"}, {"unexpected"}} {
		output, err := exec.Command(binary, args...).CombinedOutput()
		var exit *exec.ExitError

		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Errorf("args=%q exit=%v output=%q", args, err, output)
		}
	}
}
