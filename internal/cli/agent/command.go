// Package agent exposes the gateway role command.
package agent

import (
	"github.com/spf13/cobra"

	nodeapp "github.com/StasOkhrym/homeharbor/internal/app/node"
	"github.com/StasOkhrym/homeharbor/internal/cli/nodecmd"
)

// NewCommand creates a fresh agent command without starting the node.
func NewCommand() *cobra.Command {
	command := nodecmd.NewCommand(nodeapp.Gateway)
	command.AddCommand(newEnrollCommand())
	return command
}
