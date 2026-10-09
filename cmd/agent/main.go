package main

import (
	"context"
	"os"

	agentcli "github.com/StasOkhrym/homeharbor/internal/cli/agent"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := host.SignalContext(context.Background(), host.DefaultDrainTimeout)
	defer stop()

	status := host.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, agentcli.NewCommand())
	// The pre-Cobra node CLI used exit 1 for syntax errors.
	if status == 2 {
		return 1
	}

	return status
}
