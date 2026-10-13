// Package client exposes the client role command.
package client

import (
	"runtime"

	"github.com/spf13/cobra"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
	"github.com/StasOkhrym/homeharbor/internal/cli/nodecmd"
	"github.com/StasOkhrym/homeharbor/internal/client/macos"
)

// NewCommand creates a fresh client command without starting the node.
func NewCommand() *cobra.Command {
	command := nodecmd.NewCommand(nodeapp.Client)
	command.AddCommand(
		newJoinCommand(),
		newNetworkHelperCommand(),
		newNetworkCloseCommand(macos.NewInstalledHelper(), runtime.GOOS),
	)
	return command
}
