// Command healthcheck is a small Go probe copied into distroless images.
// It avoids assuming that curl, wget, or a shell exists in the container.
package main

import (
	"context"
	"os"

	healthcheckcli "github.com/StasOkhrym/homeharbor/internal/cli/healthcheck"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := host.SignalContext(context.Background(), host.DefaultDrainTimeout)
	defer stop()

	return host.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, healthcheckcli.NewCommand())
}
