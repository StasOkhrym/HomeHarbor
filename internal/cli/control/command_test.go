package control

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func controlConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.toml")
	file := `[server]
listen_address = ":8080"
public_url = "https://control.example"
[database]
url = "postgres://user@db/home"
[auth]
rp_id = "control.example"
rp_origin = "https://control.example"
session_signing_key = "01234567890123456789012345678901"
ceremony_encryption_key = "abcdefghijklmnopqrstuvwxyzABCDEF"
session_ttl = "12h"
ceremony_ttl = "5m"
[relay]
public_url = "https://relay.example"
ticket_key = "01234567890123456789012345678901"
[security]
root_public_key_file = "root.pub"
`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestControlHelpAndVersionDoNotLoadConfigOrStartRuntime(t *testing.T) {
	for _, arg := range []string{"--help", "--version"} {
		t.Run(arg, func(t *testing.T) {
			started := false
			var stdout, stderr bytes.Buffer

			code := host.Execute(context.Background(),
				[]string{"--config", "/definitely/missing/control.toml", arg},
				&stdout, &stderr,
				newCommand(func(context.Context, config.Control, *slog.Logger) error {
					started = true
					return errors.New("unexpected runtime start")
				}),
			)

			if code != 0 || started || stdout.Len() == 0 || stderr.Len() != 0 {
				t.Fatalf(
					"exit=%d started=%v stdout=%q stderr=%q",
					code, started, stdout.String(), stderr.String(),
				)
			}
		})
	}
}

func TestControlUsageAndConfigErrorsDoNotStartRuntime(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{name: "unknown flag", args: []string{"--not-a-flag"}, want: 2},
		{name: "positional argument", args: []string{"surprise"}, want: 2},
		{name: "missing config", args: []string{"--config", "/definitely/missing/control.toml"}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := false
			var stdout, stderr bytes.Buffer

			code := host.Execute(context.Background(), tc.args, &stdout, &stderr,
				newCommand(func(context.Context, config.Control, *slog.Logger) error {
					started = true
					return nil
				}),
			)

			if code != tc.want || started || stderr.Len() == 0 || stdout.Len() != 0 {
				t.Fatalf(
					"exit=%d started=%v stdout=%q stderr=%q",
					code, started, stdout.String(), stderr.String(),
				)
			}
		})
	}
}

func TestControlPassesConfigAndContextToRuntime(t *testing.T) {
	path := controlConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	called := false
	var stdout, stderr bytes.Buffer

	code := host.Execute(ctx, []string{"--config", path}, &stdout, &stderr,
		newCommand(func(gotCtx context.Context, cfg config.Control, logger *slog.Logger) error {
			called = true

			if gotCtx != ctx || cfg.Server.ListenAddress != ":8080" || logger == nil {
				t.Fatalf(
					"runtime received context/config/logger = %v/%q/%v",
					gotCtx, cfg.Server.ListenAddress, logger,
				)
			}

			return errors.New("runtime stopped")
		}),
	)

	if code != 1 || !called ||
		stderr.String() != "run control: runtime stopped\n" || stdout.Len() != 0 {
		t.Fatalf(
			"exit=%d called=%v stdout=%q stderr=%q",
			code, called, stdout.String(), stderr.String(),
		)
	}
}

func TestControlCancellationCannotReportSuccess(t *testing.T) {
	path := controlConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr bytes.Buffer

	code := host.Execute(ctx, []string{"--config", path}, &stdout, &stderr,
		newCommand(func(context.Context, config.Control, *slog.Logger) error {
			cancel()
			return nil
		}),
	)

	if code != 130 || !strings.Contains(stderr.String(), context.Canceled.Error()) {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
}

func TestControlCanceledBeforeRunDoesNotLoadConfigOrStartRuntime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	started := false
	var stdout, stderr bytes.Buffer

	code := host.Execute(ctx, []string{"--config", "/definitely/missing/control.toml"},
		&stdout, &stderr, newCommand(func(context.Context, config.Control, *slog.Logger) error {
			started = true
			return nil
		}))

	if code != 130 || started || !strings.Contains(stderr.String(), context.Canceled.Error()) {
		t.Fatalf("exit=%d started=%v stderr=%q", code, started, stderr.String())
	}
}

func TestControlCommandsHaveIndependentFlags(t *testing.T) {
	first := NewCommand()
	second := NewCommand()

	if err := first.Flags().Set("config", "first.toml"); err != nil {
		t.Fatal(err)
	}

	if got := second.Flags().Lookup("config").Value.String(); got != "config/control.toml" {
		t.Fatalf("second command inherited first command flag: %q", got)
	}
}
