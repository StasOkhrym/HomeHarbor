package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentRejectsUnsignedKernelModeBeforeCreatingIdentity(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "agent")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build agent: %v: %s", err, output)
	}
	for _, args := range [][]string{
		{"-wg-interface", "wg0"},
		{"-wg-interface", "wg0", "-coordination", "wss://control.example.com/api/v1/coordination"},
	} {
		state := filepath.Join(t.TempDir(), "agent.json")
		args = append(args, "-state", state)
		output, err := exec.Command(binary, args...).CombinedOutput()
		if err == nil || !strings.Contains(string(output), "signed coordination") {
			t.Errorf(
				"unsigned kernel configuration accepted or failed for wrong reason: %v: %s",
				err,
				output,
			)
		}
		if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("invalid runtime created identity: %v", err)
		}
	}
}
