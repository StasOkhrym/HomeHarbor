package migrate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

type trackedSession struct {
	apply  func(context.Context) error
	closed int
}

func (s *trackedSession) Apply(ctx context.Context) error { return s.apply(ctx) }
func (s *trackedSession) Close()                          { s.closed++ }

func TestMigrateHelpAndVersionDoNotReadConfigOrOpenPool(t *testing.T) {
	for _, arg := range []string{"--help", "--version"} {
		opened := false
		var out, errOut bytes.Buffer

		root := newCommand(func(context.Context, config.Database) (migrationSession, error) {
			opened = true
			return nil, errors.New("unexpected open")
		})

		code := host.Execute(
			context.Background(),
			[]string{"--config", "/missing/migrate.toml", arg},
			&out,
			&errOut,
			root,
		)

		if code != 0 || opened {
			t.Fatalf("%s: exit=%d opened=%v stderr=%q", arg, code, opened, errOut.String())
		}
	}
}

func TestMigrateClosesSessionAndPassesCommandContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.toml")

	if err := os.WriteFile(
		path,
		[]byte("[database]\nurl = 'postgres://localhost/test'\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, tc := range []struct {
		name  string
		ctx   context.Context
		apply func(context.Context) error
		want  int
	}{
		{name: "success", ctx: context.Background(), apply: func(context.Context) error { return nil }, want: 0},
		{name: "error", ctx: context.Background(), apply: func(context.Context) error { return errors.New("apply failed") }, want: 1},
		{name: "canceled after open", ctx: canceled, apply: func(ctx context.Context) error { cancel(); return ctx.Err() }, want: 130},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := &trackedSession{apply: tc.apply}
			var out, errOut bytes.Buffer

			root := newCommand(
				func(ctx context.Context, cfg config.Database) (migrationSession, error) {
					if ctx != tc.ctx || cfg.URL != "postgres://localhost/test" {
						t.Fatalf("open context/config = %v/%q", ctx, cfg.URL)
					}

					return session, nil
				},
			)

			code := host.Execute(tc.ctx, []string{"--config", path}, &out, &errOut, root)

			if code != tc.want || session.closed != 1 {
				t.Fatalf(
					"exit=%d closed=%d want exit=%d stderr=%q",
					code,
					session.closed,
					tc.want,
					errOut.String(),
				)
			}
			if tc.want == 0 && !strings.Contains(out.String(), "migrations complete") {
				t.Fatalf("missing success output: %q", out.String())
			}
			if tc.want != 0 && strings.Contains(out.String(), "migrations complete") {
				t.Fatalf("false success output: %q", out.String())
			}
		})
	}
}

func TestMigrateCancellationAfterApplySuppressesSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.toml")

	if err := os.WriteFile(
		path,
		[]byte("[database]\nurl = 'postgres://localhost/test'\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &trackedSession{apply: func(context.Context) error {
		cancel()
		return nil
	}}
	var out, errOut bytes.Buffer

	root := newCommand(func(context.Context, config.Database) (migrationSession, error) {
		return session, nil
	})

	code := host.Execute(ctx, []string{"--config", path}, &out, &errOut, root)

	if code != 130 || session.closed != 1 || strings.Contains(out.String(), "migrations complete") {
		t.Fatalf(
			"exit=%d closed=%d stdout=%q stderr=%q",
			code,
			session.closed,
			out.String(),
			errOut.String(),
		)
	}
}

func TestMigrateCanceledBeforeOpenDoesNotConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	opened := false
	var out, errOut bytes.Buffer

	root := newCommand(func(context.Context, config.Database) (migrationSession, error) {
		opened = true
		return nil, errors.New("unexpected open")
	})

	if code := host.Execute(ctx, nil, &out, &errOut, root); code != 130 || opened {
		t.Fatalf("canceled startup: exit=%d opened=%v stderr=%q", code, opened, errOut.String())
	}
}
