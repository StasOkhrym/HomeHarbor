package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/sokhrym/go-tunnels/internal/node"
	"os"
	"time"
)

func main() {
	statePath := flag.String("state", "state/client.json", "node state file")
	controlURL := flag.String("control", "", "control plane URL")
	token := flag.String("token", "", "one-time enrollment token")
	name := flag.String("name", "linux-client", "device name")
	flag.Parse()
	state, err := node.NewState()
	if err == nil && *controlURL != "" && *token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = node.Enroll(ctx, nil, *controlURL, *token, *name, &state)
	}
	if err == nil {
		err = state.Save(*statePath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("client enrolled: %s\n", state.DeviceID)
}
