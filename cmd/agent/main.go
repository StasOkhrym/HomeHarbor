package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
)

func main() {
	cfg, err := nodeapp.ParseConfig(nodeapp.Gateway, os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err == nil {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		err = nodeapp.RunCommand(ctx, nodeapp.Gateway, cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
