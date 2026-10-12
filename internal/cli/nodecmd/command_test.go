package nodecmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func TestExplicitFlagsWinOverFileIncludingFalseZeroAndEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	data := []byte(
		"[node]\nname = 'from-file'\nrefresh = true\nstate_path = 'private/state.json'\nca_file = 'file-ca.pem'\n" +
			"enrollment_token_file = '/definitely/missing/token'\n[wireguard]\nlisten_port = 12345\n",
	)

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, role := range []nodeapp.Role{nodeapp.Client, nodeapp.Gateway} {
		t.Run(roleName(role), func(t *testing.T) {
			var got config.Node
			var called bool

			cmd := newCommand(
				role,
				func(_ context.Context, actualRole nodeapp.Role, cfg config.Node) error {
					if actualRole != role {
						t.Errorf("runner received role %d, want %d", actualRole, role)
					}

					called, got = true, cfg

					return nil
				},
			)
			var out, errOut bytes.Buffer

			code := host.Execute(context.Background(), []string{
				"--config", path, "--name=", "--refresh=false", "--wg-port=0", "--token=selected",
				"--ca-file=explicit-ca.pem",
			}, &out, &errOut, cmd)

			if code != 0 || !called {
				t.Fatalf("code=%d called=%v stderr=%s", code, called, errOut.String())
			}
			if got.Identity.Name != "" || got.Identity.Refresh || got.WireGuard.ListenPort != 0 ||
				got.Identity.Token != "selected" || got.Identity.StatePath != "private/state.json" ||
				got.Identity.CAFile != "explicit-ca.pem" {
				t.Fatalf("flag precedence lost: %+v", got)
			}
		})
	}
}

func TestHelpDoesNotReadConfigOrStartNode(t *testing.T) {
	called := false

	cmd := newCommand(nodeapp.Client, func(context.Context, nodeapp.Role, config.Node) error {
		called = true
		return nil
	})
	var out, errOut bytes.Buffer

	code := host.Execute(context.Background(), []string{
		"--config", "/definitely/missing/node.toml", "--help",
	}, &out, &errOut, cmd)

	if code != 0 || called || out.Len() == 0 {
		t.Fatalf(
			"code=%d called=%v stdout=%q stderr=%q",
			code,
			called,
			out.String(),
			errOut.String(),
		)
	}
}

func TestCanceledNodeDoesNotStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	called := false

	cmd := newCommand(nodeapp.Gateway, func(context.Context, nodeapp.Role, config.Node) error {
		called = true
		return nil
	})
	var out, errOut bytes.Buffer

	code := host.Execute(ctx, nil, &out, &errOut, cmd)

	if code != 130 || called {
		t.Fatalf("canceled node: code=%d called=%v stderr=%q", code, called, errOut.String())
	}
}

func TestCommandsDoNotShareFlags(t *testing.T) {
	first := newCommand(
		nodeapp.Client,
		func(context.Context, nodeapp.Role, config.Node) error { return nil },
	)

	second := newCommand(
		nodeapp.Client,
		func(context.Context, nodeapp.Role, config.Node) error { return nil },
	)
	var out, errOut bytes.Buffer

	if code := host.Execute(
		context.Background(),
		[]string{"--name=changed", "--help"},
		&out,
		&errOut,
		first,
	); code != 0 {
		t.Fatalf("first help: %d: %s", code, errOut.String())
	}

	if flag := second.Flags().
		Lookup("name"); flag == nil || flag.Changed ||
		flag.Value.String() != "linux-client" {
		t.Fatalf("second command inherited first flags: %+v", flag)
	}
}

func TestInvalidConfigAndPositionalArgumentsNeverStartNode(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "missing config", args: []string{"--config", "/definitely/missing/node.toml"}},
		{name: "positional argument", args: []string{"unexpected"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false

			cmd := newCommand(
				nodeapp.Client,
				func(context.Context, nodeapp.Role, config.Node) error {
					called = true
					return nil
				},
			)
			var out, errOut bytes.Buffer

			code := host.Execute(context.Background(), tc.args, &out, &errOut, cmd)

			if code == 0 || called {
				t.Fatalf("code=%d called=%v stderr=%q", code, called, errOut.String())
			}
		})
	}
}
