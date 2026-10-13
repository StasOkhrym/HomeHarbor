package nodecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
)

func TestIdentityCommandExportsOnlyJoinedPublicIdentityForBothRoles(t *testing.T) {
	state, err := node.NewState()
	if err != nil {
		t.Fatal(err)
	}
	state.DeviceID, state.DeviceCredential = "joined-device", "private-credential"
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []nodeapp.Role{nodeapp.Client, nodeapp.Gateway} {
		var out, errOut bytes.Buffer
		code := host.Execute(
			context.Background(),
			[]string{"identity", "--state", path},
			&out,
			&errOut,
			NewCommand(role),
		)
		if code != 0 {
			t.Fatalf("identity command failed: %d %s", code, errOut.String())
		}
		var public map[string]string
		if err := json.Unmarshal(out.Bytes(), &public); err != nil {
			t.Fatal(err)
		}
		if len(public) != 3 || public["device_id"] != "joined-device" ||
			public["identity_public_key"] != state.IdentityPublicKey ||
			public["wireguard_public_key"] != state.WireGuard.PublicKey {
			t.Fatal("identity output was not the exact public projection")
		}
		for _, secret := range []string{state.DeviceCredential, state.IdentityPrivateKey, state.WireGuard.PrivateKey} {
			if strings.Contains(out.String()+errOut.String(), secret) {
				t.Fatal("identity exposed private state")
			}
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("inspection changed state")
		}
	}
}

func TestIdentityCommandRejectsUnsafeOrUnjoinedState(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "unjoined", "symlink", "active"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "node.json")
			state, err := node.NewState()
			if err != nil {
				t.Fatal(err)
			}
			if mode != "unjoined" {
				state.DeviceID, state.DeviceCredential = "joined", "private"
			}
			switch mode {
			case "missing":
			case "corrupt":
				if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(dir, "target.json")
				if err := state.Save(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			default:
				if err := state.Save(path); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "active" {
				store, err := localstate.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = store.Close() }()
			}
			var out, errOut bytes.Buffer
			code := host.Execute(
				context.Background(),
				[]string{"identity", "--state", path},
				&out,
				&errOut,
				NewCommand(nodeapp.Client),
			)
			if code == 0 || out.Len() != 0 {
				t.Fatal("unsafe/unjoined state emitted public admission")
			}
			if mode == "missing" {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("inspection created identity")
				}
			}
		})
	}
}

func TestIdentityCommandHelpAndCancellationHaveNoEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "node.json")
	for _, help := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		args := []string{"identity", "--state", path}
		if help {
			args = append(args, "--help")
		} else {
			cancel()
		}

		var out, errOut bytes.Buffer

		code := host.Execute(ctx, args, &out, &errOut, NewCommand(nodeapp.Client))

		cancel()

		if help && code != 0 || !help && code != 130 {
			t.Fatalf("unexpected status: %d %s", code, errOut.String())
		}

		if _, err := os.Lstat(filepath.Dir(path)); !os.IsNotExist(err) {
			t.Fatal("help/cancellation wrote state directory")
		}
	}
}
