package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sokhrym/go-tunnels/internal/node"
)

func main() {
	statePath := flag.String("state", "state/agent.json", "node state file")
	controlURL := flag.String("control", "", "control plane URL")
	token := flag.String("token", "", "one-time gateway enrollment token")
	refresh := flag.Bool("refresh", false, "rotate the existing device credential")
	name := flag.String("name", "linux-gateway", "device name")
	flag.Parse()
	state, err := node.LoadOrCreate(*statePath)
	if err == nil && *controlURL != "" && *token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = node.Enroll(ctx, nil, *controlURL, *token, *name, &state)
	} else if err == nil && *controlURL != "" && *refresh {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = node.RefreshCredential(ctx, nil, *controlURL, &state)
	}
	if err == nil {
		err = state.Save(*statePath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("gateway enrolled: %s\n", state.DeviceID)
}
