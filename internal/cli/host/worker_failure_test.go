//go:build !windows

package host

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

	"github.com/spf13/cobra"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

func TestEssentialWorkerFailureBoundsProcessWithoutClosingLiveOwners(t *testing.T) {
	for _, mode := range []string{"error", "nil", "graceful"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestWorkerFailureProcessHelper$")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "HOMEHARBOR_") {
					command.Env = append(command.Env, value)
				}
			}
			command.Env = append(
				command.Env,
				"HOMEHARBOR_WORKER_TEST_MODE="+mode,
				"HOMEHARBOR_WORKER_TEST_PATH="+directory,
			)
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { finished <- command.Wait() }()
			var result error
			select {
			case result = <-finished:
			case <-time.After(3 * time.Second):
				_ = command.Process.Kill()
				<-finished
				t.Fatal("unexpected essential exit left the process without a drain deadline")
			}
			var exit *exec.ExitError
			wantCode := 130
			if mode == "graceful" {
				wantCode = 1
			}
			if !errors.As(result, &exit) || exit.ExitCode() != wantCode {
				t.Fatalf("exit=%v want=%d output=%s", result, wantCode, output.String())
			}
			if _, err := os.Stat(filepath.Join(directory, "draining")); err != nil {
				t.Fatalf("sibling was not canceled: %v", err)
			}
			for _, name := range []string{"owner-closed", "stores-closed"} {
				_, err := os.Stat(filepath.Join(directory, name))
				if mode == "graceful" {
					if err != nil {
						t.Fatalf("joined ownership did not close %s: %v", name, err)
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("live ownership was closed early: %s: %v", name, err)
				}
			}
			if mode == "graceful" &&
				(!strings.Contains(output.String(), "synthetic dependency failure") || !strings.Contains(output.String(), "node-1")) {
				t.Fatalf("original named failure lost: %s", output.String())
			}
		})
	}
}

func TestWorkerFailureProcessHelper(t *testing.T) {
	mode := os.Getenv("HOMEHARBOR_WORKER_TEST_MODE")
	if mode == "" {
		return
	}
	directory := os.Getenv("HOMEHARBOR_WORKER_TEST_PATH")
	ctx, stop := SignalContext(context.Background(), 150*time.Millisecond)
	started := make(chan struct{})
	root := &cobra.Command{
		Use: "worker-runtime",
		RunE: func(command *cobra.Command, _ []string) error {
			defer func() { _ = os.WriteFile(filepath.Join(directory, "stores-closed"), nil, 0o600) }()
			app := nodeapp.New(
				lifecycle.Func(func(context.Context) error {
					<-started
					if mode == "nil" {
						return nil
					}
					return errors.New("synthetic dependency failure")
				}),
				lifecycle.Func(func(ctx context.Context) error {
					defer func() { _ = os.WriteFile(filepath.Join(directory, "owner-closed"), nil, 0o600) }()
					close(started)
					<-ctx.Done()
					if err := os.WriteFile(
						filepath.Join(directory, "draining"),
						nil,
						0o600,
					); err != nil {
						return err
					}
					if mode != "graceful" {
						select {}
					}
					return nil
				}),
			)
			return app.Run(command.Context())
		},
	}
	code := Execute(ctx, nil, os.Stdout, os.Stderr, root)
	stop()
	os.Exit(code)
}
