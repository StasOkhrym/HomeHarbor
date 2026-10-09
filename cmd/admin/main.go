// Command admin is the local trusted companion preview. Root private keys and
// invite codes remain on the Mac; remote requests carry signed proofs.
package main

import (
	"context"
	"os"

	admincli "github.com/StasOkhrym/homeharbor/internal/cli/admin"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := host.SignalContext(context.Background(), host.DefaultDrainTimeout)
	defer stop()

	return host.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, admincli.NewCommand())
}
