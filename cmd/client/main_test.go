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
	output, err := exec.Command(binary, "-wg-interface", "wg0", "-state", state).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "signed coordination") {
		t.Errorf("unsigned kernel client accepted: %v: %s", err, output)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("invalid runtime created identity: %v", err)
	}
}
