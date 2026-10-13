//go:build !windows

package nodecmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

// A real child signal/exit boundary detects premature process death even when
// both the forced exit and an orderly canceled command return status 130.
func TestNodeConfigurationAllowsCleanupPastInitialSignalDefault(t *testing.T) {
	for _, role := range []string{"client", "agent"} {
		t.Run(role, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "node.toml")

			if err := os.WriteFile(
				path,
				[]byte("[runtime]\nshutdown_timeout='1s'\n"),
				0o600,
			); err != nil {
				t.Fatal(err)
			}

			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}

			command := exec.Command(executable, "-test.run=^TestNodeDrainProcessHelper$")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "HOMEHARBOR_") {
					command.Env = append(command.Env, value)
				}
			}

			command.Env = append(
				command.Env,
				"HOMEHARBOR_DRAIN_TEST_ROLE="+role,
				"HOMEHARBOR_DRAIN_TEST_PATH="+path,
			)
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output

			if err := command.Start(); err != nil {
				t.Fatal(err)
			}

			finished := make(chan error, 1)
			go func() { finished <- command.Wait() }()
			t.Cleanup(func() { _ = command.Process.Kill() })
			ready := filepath.Join(directory, "ready")
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				}

				select {
				case err := <-finished:
					t.Fatalf("child failed before ready: %v: %s", err, output.String())
				default:
				}

				if time.Now().After(deadline) {
					t.Fatal("child did not enter configured runner")
				}

				time.Sleep(5 * time.Millisecond)
			}

			if err := command.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}

			select {
			case err := <-finished:
				var exit *exec.ExitError

				if !errors.As(err, &exit) || exit.ExitCode() != 130 {
					t.Fatalf("exit=%v output=%s", err, output.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("configured node did not finish drain")
			}

			if _, err := os.Stat(filepath.Join(directory, "closed")); err != nil {
				t.Fatalf("configured drain killed owned cleanup: %v: %s", err, output.String())
			}
		})
	}
}

func TestNodeDrainProcessHelper(t *testing.T) {
	name := os.Getenv("HOMEHARBOR_DRAIN_TEST_ROLE")
	if name == "" {
		return
	}

	path := os.Getenv("HOMEHARBOR_DRAIN_TEST_PATH")
	role := nodeapp.Client
	if name == "agent" {
		role = nodeapp.Gateway
	}

	ctx, stop := host.SignalContext(context.Background(), 20*time.Millisecond)

	command := newCommand(role, func(ctx context.Context, _ nodeapp.Role, _ config.Node) error {
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "ready"), nil, 0o600); err != nil {
			return err
		}

		<-ctx.Done()
		time.Sleep(100 * time.Millisecond)
		return os.WriteFile(filepath.Join(filepath.Dir(path), "closed"), nil, 0o600)
	})

	code := host.Execute(ctx, []string{"--config", path}, os.Stdout, os.Stderr, command)

	stop()
	os.Exit(code)
}
