package main

import (
	"context"
	"os"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	migratecli "github.com/StasOkhrym/homeharbor/internal/cli/migrate"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := host.SignalContext(context.Background(), host.DefaultDrainTimeout)
	defer stop()

	return host.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, migratecli.NewCommand())
}
