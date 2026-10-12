// Package client exposes the client role command.
package client

import (
	"github.com/spf13/cobra"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
	"github.com/StasOkhrym/homeharbor/internal/cli/nodecmd"
)

// NewCommand creates a fresh client command without starting the node.
func NewCommand() *cobra.Command {
	command := nodecmd.NewCommand(nodeapp.Client)
	command.AddCommand(newJoinCommand(), newNetworkHelperCommand())
	return command
}
