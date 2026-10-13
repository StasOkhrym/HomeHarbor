package macos

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstalledHelperUsesFixedArgumentsAndPrivateStdin(t *testing.T) {
	_, envelope, plan, _, private := nativeFixtureWithKey(t)
	request := HelperRequest{
		Version:    1,
		Action:     "apply",
		Envelope:   envelope,
		Plan:       plan,
		PrivateKey: private,
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sudo")
	script := "#!/bin/sh\n[ \"$#\" -eq 4 ] && [ \"$1\" = -n ] && [ \"$2\" = -- ] && [ \"$3\" = /fixed/client ] && [ \"$4\" = network-helper ] || exit 9\n[ -z \"$HOMEHARBOR_INHERITED_TEST\" ] || exit 10\ncat > \"$0.input\"\n"

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOMEHARBOR_INHERITED_TEST", "must-not-reach-helper")
	helper := installedHelper{sudoPath: path, clientPath: "/fixed/client"}

	if err := helper.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path + ".input")

	if err != nil || !bytes.Equal(data, helperJSON(t, request)) {
		t.Fatal("signed helper request was not sent exclusively through stdin")
	}

	if err := os.WriteFile(path, []byte("#!/bin/sh\ncat >&2\nexit 17\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := helper.Execute(
		context.Background(),
		request,
	); err == nil ||
		strings.Contains(err.Error(), private) {
		t.Fatal("helper failure lost its exit status or exposed private stdin")
	}
}

func TestInstalledHelperRejectsOversizedRequestBeforeLaunch(t *testing.T) {
	helper := installedHelper{sudoPath: "/must-not-run", clientPath: "/fixed/client"}
	request := HelperRequest{
		Version:    1,
		Action:     "apply",
		PrivateKey: strings.Repeat("x", MaxHelperRequestBytes),
	}

	if err := helper.Execute(
		context.Background(),
		request,
	); err == nil ||
		!strings.Contains(err.Error(), "size bound") {
		t.Fatalf("oversized private request reached process launch: %v", err)
	}
}

func TestInstalledHelperHonorsDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sudo")

	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec /bin/sleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	if err := (installedHelper{sudoPath: path, clientPath: "/fixed/client"}).Execute(
		ctx,
		HelperRequest{Version: 1, Action: "close"},
	); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("helper ignored operation deadline: %v", err)
	}
}
