package main

import (
	"context"
	"os"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	relaycli "github.com/StasOkhrym/homeharbor/internal/cli/relay"
)

// Runtime shutdown may take up to one minute; leave a short margin before
// forcing a stuck handler or upgraded session to exit without claiming success.
const relayDrainTimeout = 65 * time.Second

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := host.SignalContext(context.Background(), relayDrainTimeout)
	defer stop()

	return host.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, relaycli.NewCommand())
}
