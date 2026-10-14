package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/client/macos"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	nodetest "github.com/StasOkhrym/homeharbor/internal/testutil/node"
)

type cleanupHelper struct {
	requests []macos.HelperRequest
	err      error
}

func (h *cleanupHelper) Execute(ctx context.Context, request macos.HelperRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	h.requests = append(h.requests, request)

	return h.err
}

func networkCloseFixture(t *testing.T) (string, string, node.State, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "client.json")

	state, err := node.NewState()
	if err != nil {
		t.Fatal(err)
	}

	state.DeviceID, state.DeviceCredential = "client-1", "expired-private-credential"
	state.CredentialExpiresAt = time.Now().Add(-time.Hour)

	if err := nodetest.Save(state, statePath); err != nil {
		t.Fatal(err)
	}

	root, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	public := base64.RawURLEncoding.EncodeToString(root)
	rootPath := filepath.Join(dir, "root.pub")

	if err := os.WriteFile(rootPath, []byte(public), 0o600); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "client.toml")
	config := fmt.Sprintf(
		"[node]\nstate_path = %q\ncontrol_url = 'https://unreachable.invalid'\nca_file = '/unavailable-ca'\n[coordination]\nnetwork_id = 'sandbox-network'\nroot_public_key_file = %q\n[native]\nenabled = true\n",
		statePath,
		rootPath,
	)

	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOMEHARBOR_NODE_STATE_PATH", statePath)
	t.Setenv("HOMEHARBOR_NODE_ENROLLMENT_TOKEN_FILE", "")
	t.Setenv("HOMEHARBOR_NODE_RELAY_TICKET_FILE", "")
	return configPath, statePath, state, public
}

func TestNetworkCloseWorksOfflineWithExpiredCredentialAndPreservesIdentity(t *testing.T) {
	path, statePath, state, public := networkCloseFixture(t)

	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	helper := &cleanupHelper{}
	var stdout, stderr bytes.Buffer

	code := host.Execute(
		context.Background(),
		[]string{"--config", path},
		&stdout,
		&stderr,
		newNetworkCloseCommand(helper, "darwin"),
	)

	if code != 0 || len(helper.requests) != 1 {
		t.Fatalf("offline cleanup failed: %d %s", code, stderr.String())
	}

	request := helper.requests[0]

	if request.Action != "close" || request.Version != 1 || request.PrivateKey != "" ||
		request.Owner == nil ||
		request.Owner.NetworkID != "sandbox-network" ||
		request.Owner.DeviceID != "client-1" ||
		request.Owner.RootPublicKey != public {
		t.Fatal("cleanup did not bind the configured public owner")
	}

	after, err := os.ReadFile(statePath)

	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("cleanup rewrote client identity or credentials")
	}

	for _, secret := range []string{state.WireGuard.PrivateKey, state.IdentityPrivateKey, state.DeviceCredential} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatal("cleanup exposed private state")
		}
	}
}

func TestNetworkCloseRejectsMissingCorruptOrActiveStateBeforeHelper(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "active"} {
		t.Run(mode, func(t *testing.T) {
			path, statePath, _, _ := networkCloseFixture(t)
			switch mode {
			case "missing":
				if err := os.Remove(statePath); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(statePath, []byte("{broken"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "active":
				owner, err := localstate.Open(statePath)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = owner.Close() }()
			}

			helper := &cleanupHelper{}
			var stdout, stderr bytes.Buffer

			code := host.Execute(
				context.Background(),
				[]string{"--config", path},
				&stdout,
				&stderr,
				newNetworkCloseCommand(helper, "darwin"),
			)

			if code == 0 || len(helper.requests) != 0 {
				t.Fatal("unsafe recovery state reached helper")
			}

			if mode == "missing" {
				if _, err := os.Lstat(statePath); !os.IsNotExist(err) {
					t.Fatal("recovery created a new identity")
				}
			}
		})
	}
}

func TestNetworkCloseHelpAndUnsupportedPlatformHaveNoEffects(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows"} {
		helper := &cleanupHelper{}
		var stdout, stderr bytes.Buffer

		code := host.Execute(
			context.Background(),
			[]string{"--config", "/must-not-read", "--help"},
			&stdout,
			&stderr,
			newNetworkCloseCommand(helper, platform),
		)

		if code != 0 || len(helper.requests) != 0 {
			t.Fatal("cleanup help caused effects")
		}

		if platform != "darwin" {
			code = host.Execute(
				context.Background(),
				[]string{"--config", "/must-not-read"},
				&stdout,
				&stderr,
				newNetworkCloseCommand(helper, platform),
			)

			if code == 0 || !strings.Contains(stderr.String(), "macOS") ||
				len(helper.requests) != 0 {
				t.Fatal("unsupported platform reached recovery effects")
			}
		}
	}
}

func TestNetworkCloseReportsHelperFailureWithoutSuccess(t *testing.T) {
	path, statePath, _, _ := networkCloseFixture(t)

	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	helper := &cleanupHelper{err: errors.New("native resource ownership conflict")}
	var stdout, stderr bytes.Buffer

	code := host.Execute(
		context.Background(),
		[]string{"--config", path},
		&stdout,
		&stderr,
		newNetworkCloseCommand(helper, "darwin"),
	)

	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "ownership conflict") {
		t.Fatal("failed cleanup reported success")
	}

	after, err := os.ReadFile(statePath)

	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed cleanup changed identity state")
	}
}
