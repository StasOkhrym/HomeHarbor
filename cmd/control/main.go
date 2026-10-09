package main

import (
	"context"
	"os"
	"time"

	controlcli "github.com/StasOkhrym/homeharbor/internal/cli/control"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
)

// Allow the longest valid runtime shutdown and cleanup to finish before the
// signal host forces an unresponsive control process to exit.
const controlDrainTimeout = 130 * time.Second

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := host.SignalContext(context.Background(), controlDrainTimeout)
	defer stop()

	return host.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, controlcli.NewCommand())
}
