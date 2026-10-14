//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package localstate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func stateLockProcess(t *testing.T, path, mode string) *exec.Cmd {
	t.Helper()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, executable, "-test.run=^TestStateLockProcessHelper$")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "HOMEHARBOR_") {
			command.Env = append(command.Env, value)
		}
	}

	command.Env = append(command.Env,
		"HOMEHARBOR_STATE_LOCK_TEST_PATH="+path,
		"HOMEHARBOR_STATE_LOCK_TEST_MODE="+mode,
	)

	return command
}

func TestStateOwnerExcludesAnotherProcessUntilClose(t *testing.T) {
	store := openTestStore(t)

	if err := store.Replace([]byte("fixture-identity")); err != nil {
		t.Fatal(err)
	}

	output, err := stateLockProcess(t, store.path, "probe").CombinedOutput()

	if err != nil || !strings.HasPrefix(string(output), "BUSY\n") {
		t.Fatalf("other process did not observe ownership: %v, %s", err, output)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	output, err = stateLockProcess(t, store.path, "probe").CombinedOutput()

	if err != nil || !strings.HasPrefix(string(output), "OWNED:fixture-identity\n") {
		t.Fatalf("closed owner prevented identity reuse: %v, %s", err, output)
	}
}

func TestKilledProcessReleasesStateOwnerWithoutReplacingIdentity(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "state.json")

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Replace([]byte("fixture-identity")); err != nil {
		_ = store.Close()

		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	command := stateLockProcess(t, path, "hold")

	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()

	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := command.Start(); err != nil {
		t.Fatal(err)
	}

	joined := false
	defer func() {
		if !joined {
			_ = command.Process.Kill()

			_ = command.Wait()
		}
	}()

	ready, err := bufio.NewReader(stdout).ReadString('\n')

	if err != nil || ready != "OWNED:fixture-identity\n" {
		t.Fatalf("child did not acquire existing identity: %v, %q", err, ready)
	}

	other, err := Open(path)
	if err == nil {
		_ = other.Close()

		t.Fatal("parent acquired the child process's state")
	}

	if !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("ownership failure was not lock contention: %v", err)
	}

	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}

	err = command.Wait()
	joined = true
	var exit *exec.ExitError

	if !errors.As(err, &exit) {
		t.Fatalf("child did not terminate abruptly: %v", err)
	}

	recovered, err := Open(path)
	if err != nil {
		t.Fatalf("process death retained the state owner: %v", err)
	}
	defer func() { _ = recovered.Close() }()

	data, err := recovered.Read()

	if err != nil || string(data) != "fixture-identity" {
		t.Fatalf("owner recovery replaced identity: %v, %q", err, data)
	}
}

func TestStateLockProcessHelper(t *testing.T) {
	mode := os.Getenv("HOMEHARBOR_STATE_LOCK_TEST_MODE")
	if mode == "" {
		return
	}

	store, err := Open(os.Getenv("HOMEHARBOR_STATE_LOCK_TEST_PATH"))
	if errors.Is(err, unix.EWOULDBLOCK) {
		fmt.Println("BUSY")
		return
	}

	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	data, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("OWNED:%s\n", data)
	if mode == "hold" {
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			t.Fatal(err)
		}
	}
}
