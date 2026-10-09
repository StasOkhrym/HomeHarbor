package host_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	admincli "github.com/StasOkhrym/homeharbor/internal/cli/admin"
	agentcli "github.com/StasOkhrym/homeharbor/internal/cli/agent"
	clientcli "github.com/StasOkhrym/homeharbor/internal/cli/client"
	controlcli "github.com/StasOkhrym/homeharbor/internal/cli/control"
	"github.com/StasOkhrym/homeharbor/internal/cli/healthcheck"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/cli/migrate"
	relaycli "github.com/StasOkhrym/homeharbor/internal/cli/relay"
)

type roleCommand struct {
	name       string
	newCommand func() *cobra.Command
	configArgs []string
	runArgs    []string
}

func everyRole() []roleCommand {
	missing := "/definitely/missing/homeharbor.toml"
	return []roleCommand{
		{"admin", admincli.NewCommand, nil, []string{"init-root", "--config", missing}},
		{"agent", agentcli.NewCommand, []string{"--config", missing}, nil},
		{"client", clientcli.NewCommand, []string{"--config", missing}, nil},
		{"control", controlcli.NewCommand, []string{"--config", missing}, nil},
		{"healthcheck", healthcheck.NewCommand, nil, []string{"https://127.0.0.1/healthz"}},
		{"migrate", migrate.NewCommand, []string{"--config", missing}, nil},
		{"relay", relaycli.NewCommand, []string{"--config", missing}, nil},
	}
}

func TestEveryRoleHelpAndVersionHaveNoEffects(t *testing.T) {
	for _, role := range everyRole() {
		for _, arg := range []string{"--help", "--version"} {
			t.Run(role.name+"/"+arg, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				args := append(append([]string(nil), role.configArgs...), arg)

				code := host.Execute(
					context.Background(),
					args,
					&stdout,
					&stderr,
					role.newCommand(),
				)

				if code != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
			})
		}
	}
}

func TestEveryRolePreCanceledRunFailsBeforeStartup(t *testing.T) {
	for _, role := range everyRole() {
		t.Run(role.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			cancel()
			var stdout, stderr bytes.Buffer
			args := append(append([]string(nil), role.configArgs...), role.runArgs...)

			code := host.Execute(ctx, args, &stdout, &stderr, role.newCommand())

			if code != 130 || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), context.Canceled.Error()) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
