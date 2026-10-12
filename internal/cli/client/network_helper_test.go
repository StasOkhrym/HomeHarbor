package client

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
)

func TestNetworkHelperHasNoCallerSelectedPathsOrSecretFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := host.Execute(
		context.Background(),
		[]string{"network-helper", "--help"},
		&stdout,
		&stderr,
		NewCommand(),
	)

	if code != 0 {
		t.Fatalf("helper help failed: %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "signed") {
		t.Fatal("helper help does not explain signed stdin input")
	}

	for _, flag := range []string{"--state", "--config", "--policy", "--journal", "--private-key", "--executable"} {
		if strings.Contains(stdout.String(), flag) {
			t.Fatalf("privileged helper exposes caller input %s", flag)
		}
	}

	for _, args := range [][]string{
		{"network-helper", "--policy", "/tmp/foreign"},
		{"network-helper", "foreign"},
	} {
		stdout.Reset()
		stderr.Reset()

		if code := host.Execute(
			context.Background(),
			args,
			&stdout,
			&stderr,
			NewCommand(),
		); code == 0 {
			t.Fatalf("helper accepted caller-selected inputs: %v", args)
		}
	}
}
